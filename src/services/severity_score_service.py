"""SeverityScore service (Step 4/6 — domain logic for the main slot).

Assigns a severity band (CRITICAL / HIGH / MEDIUM / LOW) to each detected policy
violation and computes whether the batch requires a 48-hour notification (FSA AI
MRM). Severity is deterministic: a base weight per OWASP category (config-driven,
defaults provided) scaled by the violation's classifier confidence. The
CRITICAL→48h mapping is config-driven via ``severity_48h_bands`` (defaults to
CRITICAL only).

Produces ``{violations:[{event_id, owasp_category, severity, score,
notify_48h}], max_severity, requires_48h_notification}``.

Deterministic. Logic preserved 1:1 from the architect-spec SeverityScore node.
"""

from __future__ import annotations

from typing import Any

from src.services._support import as_float

# Default per-category base severity weight (0..1). Config may override via
# ``severity_weights``. Categories absent here default to MEDIUM weight (0.5).
DEFAULT_WEIGHTS: dict[str, float] = {
    "prompt_injection": 0.8,
    "sensitive_info_disclosure": 0.9,
    "insecure_output_handling": 0.7,
    "model_denial_of_service": 0.6,
    "supply_chain": 0.85,
    "excessive_agency": 0.7,
    "privilege_escalation": 0.95,
    "session_hijacking": 0.95,
    "repudiation_audit_gaps": 0.5,
    "cascading_failures": 0.8,
}
# Score bands → severity label. Score = weight * confidence in [0, 1].
_BANDS = (
    (0.85, "critical"),
    (0.65, "high"),
    (0.4, "medium"),
    (0.0, "low"),
)
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
DEFAULT_48H_BANDS = {"critical"}


def score(violations: list[Any], severity_weights: object = None, severity_48h_bands: object = None) -> dict[str, Any]:
    """Band each violation by severity and compute the 48h-notification flag."""
    weights = _weights(severity_weights)
    notify_bands = _notify_bands(severity_48h_bands)

    scored: list[dict[str, Any]] = []
    max_rank = -1
    requires_48h = False

    for v in violations:
        if not isinstance(v, dict):
            continue
        category = str(v.get("owasp_category", ""))
        confidence = as_float(v.get("confidence"), 0.0)
        weight = weights.get(category, 0.5)
        s = max(0.0, min(1.0, weight * confidence))
        severity = _band(s)
        notify = severity in notify_bands
        requires_48h = requires_48h or notify
        max_rank = max(max_rank, _SEVERITY_RANK[severity])
        scored.append(
            {
                "event_id": str(v.get("event_id", "")),
                "owasp_category": category,
                "severity": severity,
                "score": round(s, 3),
                "notify_48h": notify,
            }
        )

    max_severity = next((k for k, r in _SEVERITY_RANK.items() if r == max_rank), None)
    return {
        "violations": scored,
        "max_severity": max_severity,
        "requires_48h_notification": requires_48h,
    }


def _weights(override: object) -> dict[str, Any]:
    weights = dict(DEFAULT_WEIGHTS)
    if isinstance(override, dict):
        for k, val in override.items():
            weights[str(k)] = as_float(val, weights.get(str(k), 0.5))
    return weights


def _notify_bands(override: object) -> set[Any]:
    if isinstance(override, list) and override:
        return {str(b).strip().lower() for b in override}
    return set(DEFAULT_48H_BANDS)


def _band(s: float) -> str:
    for threshold, label in _BANDS:
        if s >= threshold:
            return label
    return "low"
