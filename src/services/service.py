"""Service layer overview for CMN-C1-197.

Core detection logic is deterministic and self-contained in the per-step
services (``event_stream_parse_service``, ``owasp_classify_service``,
``policy_violation_service``, ``severity_score_service``,
``incident_alert_service``, ``audit_log_service``). Policy rules, severity
weights, the remediation map, the alert format, and ``generated_at`` / ``alert_id``
are supplied by the caller via ``input_context`` — not fetched here.

One external integration exists:
``llm_classify_service`` optionally calls Azure OpenAI to enhance Step 2
classification, using the S-3 ``bound_secrets`` / ``secrets_factory`` mechanism
for credentials (never ``os.environ``) and degrading silently to the
deterministic rule table on any failure. It is the only external call in this
template; no other step reaches outside the process.

This module remains the seam where a further external integration — e.g. a live
cloud-log streaming adapter (Kafka / EventHub / CloudWatch) or a SIEM
alert-dispatch sink — would be added. It intentionally exposes no behavior today
and imports no ``agenticstar`` / ``mediator`` symbols.
"""

from __future__ import annotations
