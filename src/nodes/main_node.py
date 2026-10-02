"""MainNode — Steps 2-5/6: the OWASP detection chain (core business logic).

Runs the four core detection steps in order, each delegating to its dedicated
deterministic service so every architect-spec step is preserved 1:1:

    Step 2 OWASPTaxonomyClassify  → owasp_classify_service.classify
                                    (+ optional llm_classify_service.enhance)
    Step 3 PolicyViolationDetect  → policy_violation_service.detect
    Step 4 SeverityScore          → severity_score_service.score
    Step 5 IncidentAlert          → incident_alert_service.build_alert

Steps 3-5 are deterministic (config-driven policy, weight*confidence banding) —
NO LLM inference, no network. Step 2's deterministic rule table
(``owasp_classify_service.classify``) is the floor and is always computed first;
an OPTIONAL LLM enhancement (``llm_classify_service.enhance``, docs/02_design.md
§3) may ADD rows the rule table missed. Any enhancement
failure — missing secret, API error, malformed response, or simply no LLM
configured — degrades silently back to the rule-only baseline; it never raises
and never affects ``status``. Domain knobs (thresholds, policy rules, severity
weights, alert format, remediation map, alert_id, generated_at) flow from the
caller's ``input_context``. An S-4 audit event records the scan outcome.

On an upstream validation halt (``status == ERROR``) the slot is a no-op so the
pipeline short-circuits to finalize.

Node contract: overrides ``execute(self, state) -> dict`` only (no ``config``
param). Returns a partial update with an ``AgentStatus.*`` enum status.
"""

from __future__ import annotations

from typing import Any

from framework.nodes.function_node import FunctionNode
from shared.services.events import emitter
from shared.services.events.types import EventType
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services import incident_alert_service as alert_svc
from src.services import llm_classify_service
from src.services import owasp_classify_service as classify_svc
from src.services import policy_violation_service as policy_svc
from src.services import severity_score_service as severity_svc
from src.services._support import as_int, domain_config, dump_json, load_list


class MainNode(FunctionNode):
    """Steps 2-5 — deterministic OWASP classify → policy → severity → alert."""

    # S-1 (criterion #13): operates on internal agent execution telemetry and
    # emits security incident alerts — same floor as InitializeNode and
    # agent.yaml. Declared explicitly; implicit ANONYMOUS is not acceptable.
    required_trust_level = TrustLevel.INTERNAL

    def __init__(self, llm: Any = None) -> None:
        """``llm`` is a test-double seam only — production wiring (register_nodes)
        never passes one; the real client is built per-invocation in execute()
        from invocation-scoped secrets so it is never cached across callers."""
        super().__init__()
        self._llm = llm

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Progress (non-terminal) event for the caller. Outside the Marketplace runtime
        # this resolves to a no-op emitter, so it is safe on every entry path.
        emitter().emit_event(
            event_type=EventType.PROGRESS_UPDATE,
            message="Working on the request...",
            metadata={"step": "main"},
        )
        if state.get("status") == AgentStatus.ERROR.value:
            return {}  # upstream halt — short-circuit, preserve ERROR

        cfg = domain_config(state)

        # Step 2 — OWASP Agentic Top 10 classification (deterministic rule-table
        # floor, always computed first).
        events = load_list(state.get("parsed_events"))
        max_tool_calls = as_int(cfg.get("max_tool_calls"), classify_svc.DEFAULT_MAX_TOOL_CALLS)
        classifications = classify_svc.classify(events, max_tool_calls)

        # Optional LLM enhancement — ADDS rows the rule table missed; any
        # failure (no secret, API error, malformed response) returns None and
        # the deterministic baseline above stands unchanged.
        llm_rows = llm_classify_service.enhance(events, classifications, self._llm, state)
        if llm_rows:
            classifications = classifications + llm_rows

        # Step 3 — config-driven policy-rule evaluation.
        violations = policy_svc.detect(
            classifications,
            policy_min_confidence=cfg.get("policy_min_confidence", policy_svc.DEFAULT_MIN_CONFIDENCE),
            policy_enabled_categories=cfg.get("policy_enabled_categories"),
            policy_rules=cfg.get("policy_rules"),
        )

        # Step 4 — deterministic severity banding + FSA 48h flag.
        assessment = severity_svc.score(
            violations,
            severity_weights=cfg.get("severity_weights"),
            severity_48h_bands=cfg.get("severity_48h_bands"),
        )

        # Step 5 — config-format structured alert + per-finding remediation.
        alert = alert_svc.build_alert(
            assessment,
            alert_format=cfg.get("alert_format", alert_svc.DEFAULT_FORMAT),
            remediation_map=cfg.get("remediation_map"),
            alert_id=cfg.get("alert_id") or state.get("correlation_id") or state.get("session_id"),
            generated_at=cfg.get("generated_at"),
        )

        # S-4 — audit the scan (side-effect path; no raw PII / credentials).
        emit_trace_event(
            "owasp_runtime_scan",
            {
                "parsed_event_count": len(events),
                "violation_count": len(violations),
                "max_severity": assessment.get("max_severity"),
                "requires_48h_notification": bool(assessment.get("requires_48h_notification")),
            },
            state,
        )

        return {
            "owasp_classifications": dump_json(classifications),
            "policy_violations": dump_json(violations),
            "severity_assessment": dump_json(assessment),
            "alert_payload": dump_json(alert),
            "status": AgentStatus.SUCCESS.value,
        }
