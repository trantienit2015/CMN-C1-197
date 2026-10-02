"""CMN-C1-197 — state schema.

``OWASPAlertState`` extends the framework ``AgentState`` with the runtime
anomaly-detection pipeline's agent-specific fields. Every added field is a
**primitive** (``str`` / ``int`` / ``bool``) or a **JSON-serialized ``str``** so
the state is msgpack-safe for LangGraph checkpointing. All shared fields (``user_input``,
``input_context``, ``status``, ``session_id``, ``correlation_id``,
``node_history``, ``error_log``, ``hitl_*`` …) are inherited from ``AgentState``.

Structured collections (parsed events, classifications, violations, the alert
payload, the audit entry) are stored as **JSON-serialized ``str``** — never as
live ``list`` / ``dict`` objects. Each producing slot ``json.dumps`` on write and
each consuming slot ``json.loads`` on read (helpers ``dump_json`` / ``load_list``
/ ``load_dict`` in ``src.services._support``). A single JSON ``str`` is
unambiguously round-trippable across framework serializer versions (state-safety
guidance).

Hard rules enforced by this schema's usage (see nodes/services):
  * No Pydantic models / dataclasses / arbitrary Python objects in state.
  * No JWTs, API keys, credentials, or raw sensitive log *values* in state
    beyond what the S-3 mask redacts before the alert is emitted.
  * ``InvocationContext`` is never stored — it is reconstructed in a node via
    ``InvocationContext.from_state(state)`` when needed.
"""

from __future__ import annotations

from typing import Optional

from framework.schemas.agent_state import AgentState


class OWASPAlertState(AgentState):
    """Flat state for the OWASP Agentic runtime anomaly-detection pipeline.

    Fields are populated slot by slot:
      initialize    → raw_events (JSON str), log_source
      pre_process   → parsed_events
      main          → owasp_classifications, policy_violations,
                      severity_assessment, alert_payload
      post_process  → masked_alert, audit_log_entry, formatted_output
    """

    # ── Inputs (caller-supplied via input_context / initialize) ──────────
    # Raw AI agent execution log entries, normalized to a JSON string by
    # initialize (msgpack-safe).
    raw_events: Optional[str]
    # Cloud / agent-framework log source: "azure" | "aws" | "gcp" | "generic".
    # Selects the EventStreamParse normalization adapter; defaults to "generic".
    log_source: Optional[str]
    source_agent_id: Optional[str]

    # ── Stage outputs (JSON-serialized strings — see module docstring) ─────
    # pre_process: json.dumps([{event_id, agent_id, action_type, model, prompt,
    #   tools, response, session_id, ts}])
    parsed_events: Optional[str]
    # main: json.dumps([{event_id, owasp_category, confidence, signals}])
    owasp_classifications: Optional[str]
    # main: json.dumps([{event_id, owasp_category, rule_id, confidence,
    #   is_violation}])
    policy_violations: Optional[str]
    # main: json.dumps({violations:[{event_id, severity, notify_48h}],
    #   max_severity, requires_48h_notification})
    severity_assessment: Optional[str]
    # main: json.dumps({alert_id, format, summary, findings,
    #   requires_48h_notification, generated_at}) — alert before S-3 masking
    alert_payload: Optional[str]
    # post_process (S-3): masked rendition of alert_payload (JSON string)
    masked_alert: Optional[str]
    # post_process (S-5): json.dumps({correlation_id, ts, violations_found,
    #   alert_dispatched, agent_version, ...}) — EU AI Act Art.72 evidence
    audit_log_entry: Optional[str]
