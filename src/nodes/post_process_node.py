"""PostProcessNode — Step 6/6: S-3 masking + S-5 audit (AuditLogWrite, terminal).

The S-3 / S-5 terminal gate of the pipeline, delegating to ``audit_log_service``:

  * **S-3 (MANDATORY)** — deterministic regex masking (NOT LLM) of the serialized
    alert so any secret/PII echoed from the classified logs is redacted before
    the alert leaves the agent.
  * **S-5** — an immutable audit-log entry (EU AI Act Art. 72 evidence). Even on
    an upstream halt an audit entry is still emitted (no un-audited exit), but no
    masked alert is fabricated.

Sets ``formatted_output`` to the masked alert so the framework ``get_output()``
returns the S-3-masked alert as the agent ``output``. Emits an S-4 audit event.

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

from src.services import audit_log_service as audit_svc
from src.services._support import domain_config, dump_json, load_dict


class PostProcessNode(FunctionNode):
    """Step 6 — S-3 deterministic masking + S-5 immutable audit entry (terminal)."""

    # S-1 (criterion #13): writes the S-5 immutable audit entry for internal
    # agent telemetry — same floor as InitializeNode and agent.yaml. Declared
    # explicitly; implicit ANONYMOUS inheritance is not acceptable.
    required_trust_level = TrustLevel.INTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Progress (non-terminal) event for the caller. Outside the Marketplace runtime
        # this resolves to a no-op emitter, so it is safe on every entry path.
        emitter().emit_event(
            event_type=EventType.PROGRESS_UPDATE,
            message="Preparing the result...",
            metadata={"step": "post_process"},
        )
        cfg = domain_config(state)
        ts = cfg.get("generated_at")

        # Even on an upstream halt we still emit an audit entry (no un-audited
        # exit) but we do not fabricate a masked alert.
        if state.get("status") == AgentStatus.ERROR.value:
            audit = audit_svc.audit_entry(state, ts, masked=False, status="halted")
            emit_trace_event("owasp_audit_written", {"status": "halted"}, state)
            # Preserve the ERROR status set upstream; do not overwrite it.
            return {"audit_log_entry": dump_json(audit)}

        payload = load_dict(state.get("alert_payload"))
        masked, had_sensitive = audit_svc.mask_alert(payload)

        raw_summary = payload.get("summary")
        summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
        audit = audit_svc.audit_entry(
            state,
            ts,
            masked=True,
            status="success",
            violations_found=int(summary.get("total_violations") or 0),
            alert_dispatched=bool(payload.get("findings")),
            requires_48h_notification=bool(payload.get("requires_48h_notification")),
            s3_redactions=had_sensitive,
        )
        emit_trace_event(
            "owasp_audit_written",
            {"status": "success", "s3_redactions_applied": had_sensitive},
            state,
        )
        return {
            "masked_alert": masked,
            "audit_log_entry": dump_json(audit),
            # Surface the masked alert as the agent's canonical output.
            "formatted_output": masked,
            "status": AgentStatus.SUCCESS.value,
        }
