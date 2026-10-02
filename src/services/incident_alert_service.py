"""IncidentAlert service (Step 5/6 — domain logic for the main slot).

Composes a structured incident-alert payload from the severity assessment. The
alert *format* is config-driven (iso_42001 / nist_ai_rmf / eu_ai_act /
fsa_ai_mrm / generic) — there is **no hardcoded governance format** in code
(Cat 1 = zero domain assumption; the regulatory mapping lives in config, keeping
the template industry-agnostic). Per finding, a remediation checklist is looked
up from a config-supplied ``remediation_map`` keyed by OWASP category, defaulting
to a generic "review + contain + report" checklist.

The 48-hour FSA notification flag from SeverityScore is surfaced on the alert.

Produces ``{alert_id, format, summary, findings, requires_48h_notification,
generated_at}``.

The alert is built deterministically from the assessment (no LLM call required).
``generated_at`` / ``alert_id`` are supplied by the caller (deterministic,
testable) so runs stay reproducible — the template never reads a wall clock.

Logic preserved 1:1 from the architect-spec IncidentAlert node.
"""

from __future__ import annotations

from typing import Any

DEFAULT_FORMAT = "generic"
_KNOWN_FORMATS = {"iso_42001", "nist_ai_rmf", "eu_ai_act", "fsa_ai_mrm", "generic"}
_GENERIC_REMEDIATION = [
    "Review the flagged event in the source log stream",
    "Contain the affected agent / revoke its active session",
    "Record the finding for post-market monitoring evidence",
]


def build_alert(
    assessment: dict[str, Any],
    alert_format: str = DEFAULT_FORMAT,
    remediation_map: object = None,
    alert_id: object = None,
    generated_at: object = None,
) -> dict[str, Any]:
    """Build the structured incident-alert payload from the severity assessment."""
    fmt = str(alert_format or DEFAULT_FORMAT).strip().lower()
    if fmt not in _KNOWN_FORMATS:
        fmt = DEFAULT_FORMAT
    remediation_map = remediation_map if isinstance(remediation_map, dict) else {}

    scored = [v for v in (assessment.get("violations") or []) if isinstance(v, dict)]
    requires_48h = bool(assessment.get("requires_48h_notification"))

    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    findings: list[dict[str, Any]] = []
    for v in scored:
        category = v.get("owasp_category", "unknown")
        severity = v.get("severity", "unknown")
        by_category[category] = by_category.get(category, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
        findings.append(
            {
                "event_id": v.get("event_id"),
                "owasp_category": category,
                "severity": severity,
                "notify_48h": bool(v.get("notify_48h")),
                "remediation": _remediation(category, remediation_map),
            }
        )

    return {
        "alert_id": str(alert_id) if alert_id else None,
        "format": fmt,
        "summary": {
            "total_violations": len(findings),
            "by_category": by_category,
            "by_severity": by_severity,
            "max_severity": assessment.get("max_severity"),
            "status": "violations_detected" if findings else "clean",
        },
        "findings": findings,
        "requires_48h_notification": requires_48h,
        "generated_at": generated_at,
    }


def _remediation(category: str, remediation_map: dict[str, Any]) -> list[Any]:
    steps = remediation_map.get(category)
    if isinstance(steps, list) and steps:
        return [str(s) for s in steps]
    return list(_GENERIC_REMEDIATION)
