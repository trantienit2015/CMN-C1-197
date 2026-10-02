"""AuditLogWrite service (Step 6/6 — domain logic for the post_process slot).

The S-3 / S-5 terminal gate of the pipeline.

  * **S-3 (MANDATORY)** — deterministic masking of sensitive values in the alert
    payload (regex, NOT LLM). Masking is applied to the serialized alert so any
    secret/PII echoed from the classified logs (prompt fragments, tool
    arguments, responses) is redacted before the alert leaves the agent
   .
  * **S-5** — builds an immutable audit-log entry (JSON, timestamped) for the
    operation: correlation_id, violations found, whether an alert was dispatched,
    48h-notification flag, agent version. This is the EU AI Act Art. 72
    post-market monitoring evidence the agent exists to produce.

Produces ``masked_alert`` (the S-3-masked alert payload, JSON string) and an
``audit`` record (dict). The S-3 enforcement primitive is ``mask_sensitive`` in
``_support`` (a deterministic regex masker).

Logic preserved 1:1 from the architect-spec AuditLogWrite node.
"""

from __future__ import annotations

from typing import Any

from src.services._support import contains_sensitive, dump_json, mask_sensitive

TEMPLATE_ID = "CMN-C1-197"
AGENT_VERSION = "0.1.0"


def mask_alert(payload: dict[str, Any]) -> tuple[str, bool]:
    """S-3: mask the serialized alert. Returns (masked_json, had_sensitive)."""
    serialized = dump_json(payload) or "{}"
    had_sensitive = contains_sensitive(serialized)
    return mask_sensitive(serialized), had_sensitive


def audit_entry(
    state: dict[str, Any],
    # Caller-supplied; absent when the request does not carry generated_at.
    ts: str | None,
    *,
    masked: bool,
    status: str,
    violations_found: int = 0,
    alert_dispatched: bool = False,
    requires_48h_notification: bool = False,
    s3_redactions: bool = False,
) -> dict[str, Any]:
    """Build a PII-free immutable audit entry (S-5 / EU AI Act Art. 72)."""
    return {
        "template_id": TEMPLATE_ID,
        "agent_version": AGENT_VERSION,
        "event": "owasp_runtime_scan",
        "status": status,
        "session_id": state.get("session_id"),
        "correlation_id": state.get("correlation_id") or state.get("session_id"),
        "source_agent_id": state.get("source_agent_id"),
        "violations_found": violations_found,
        "alert_dispatched": alert_dispatched,
        "requires_48h_notification": requires_48h_notification,
        "s3_masked": masked,
        "s3_redactions_applied": s3_redactions,
        "ts": ts,
    }
