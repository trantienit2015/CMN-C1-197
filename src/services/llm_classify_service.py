"""LLM-assisted enhancement of OWASPTaxonomyClassify (Step 2/6) — OPTIONAL.

Design note (docs/02_design.md §3): the classifier was originally LLM-free for
auditability/reproducibility, with the only LLM touchpoint being an
externally-supplied narrative at the IncidentAlert step. This module adds an
optional model enhancement to the classification step itself — see
docs/02_design.md §3 for the design.

The deterministic rule table in ``owasp_classify_service.py`` remains the floor
and is never modified, weakened, or bypassed by this module:

  * This module only ever ADDS rows the rule table missed — it never removes or
    downgrades a rule-based finding.
  * Any failure (missing secret, API error, malformed/wrong-shape response, no
    events) degrades silently back to the rule-only baseline — this module
    never raises and never sets ``status=error``.
  * Event content sent to the external LLM is masked with the same S-3
    deterministic masking (``mask_sensitive``) used elsewhere in this template,
    since the very log content being classified may itself carry the secrets/PII
    this agent exists to catch.
"""

from __future__ import annotations

from typing import Any

from framework.schemas.invocation_context import InvocationContext
from shared.services.llm.azure_openai_client import AzureOpenAIClient
from shared.utils.llm_json import extract_json_object

from src.services._support import mask_sensitive

# Full OWASP Agentic Top 10 taxonomy (ASI01-ASI10) — a superset of the keys the
# deterministic rule table implements signals for today (owasp_classify_service
# covers 6 by regex + excessive_agency structurally; the remaining 3 have no rule
# signals yet). The LLM is allowed to propose any of the 10 canonical categories.
OWASP_CATEGORIES = frozenset(
    {
        "prompt_injection",
        "sensitive_info_disclosure",
        "insecure_output_handling",
        "model_denial_of_service",
        "supply_chain",
        "excessive_agency",
        "privilege_escalation",
        "session_hijacking",
        "repudiation_audit_gaps",
        "cascading_failures",
    }
)

_MAX_FIELD_CHARS = 2000
_MAX_RATIONALE_CHARS = 500

_SYSTEM_PROMPT = (
    "You are a security analyst reviewing AI agent execution log events for "
    "OWASP Agentic Top 10 violations. The allowed categories are exactly: "
    + ", ".join(sorted(OWASP_CATEGORIES))
    + ". Reply with ONLY a JSON object of the shape "
    '{"findings": [{"event_id": "...", "owasp_category": "...", '
    '"confidence": 0.0-1.0, "rationale": "..."}]}. '
    "Only report a finding you are reasonably confident about. Do not repeat "
    "any event_id/owasp_category pair listed under already_flagged."
)


def enhance(
    events: list[Any],
    baseline: list[dict[str, Any]],
    llm: Any,
    state: dict[str, Any],
) -> list[dict[str, Any]] | None:
    """Return additional classification rows the rule table missed, or ``None``.

    ``None`` means "no change" — the caller keeps its deterministic ``baseline``
    unchanged. Never raises.
    """
    try:
        payload = _event_payload(events)
        if not payload:
            return None
        already = _already_flagged(baseline)

        client = llm
        if client is None:
            ctx = InvocationContext.from_state(state)
            client = AzureOpenAIClient(
                {
                    "api_key": ctx.secrets.require("AZURE_OPENAI_API_KEY"),
                    "azure_endpoint": ctx.secrets.require("AZURE_OPENAI_ENDPOINT"),
                    "azure_deployment": ctx.secrets.require("AZURE_OPENAI_DEPLOYMENT"),
                }
            )

        response = client.complete(
            [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": _user_content(payload, already),
                },
            ]
        )
        parsed = extract_json_object(response.get("content", ""))
        rows = _validate_findings(parsed.get("findings"), payload, already)
        return rows or None
    except Exception:
        return None


def _event_payload(events: list[Any]) -> list[dict[str, str]]:
    payload: list[dict[str, str]] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        event_id = str(ev.get("event_id", ""))
        if not event_id:
            continue
        payload.append(
            {
                "event_id": event_id,
                "prompt": mask_sensitive(ev.get("prompt", ""))[:_MAX_FIELD_CHARS],
                "response": mask_sensitive(ev.get("response", ""))[:_MAX_FIELD_CHARS],
                "action_type": str(ev.get("action_type", "")),
                "tools": mask_sensitive(" ".join(str(t) for t in (ev.get("tools") or [])))[:_MAX_FIELD_CHARS],
            }
        )
    return payload


def _already_flagged(baseline: list[dict[str, Any]]) -> set[tuple[str, str]]:
    flagged: set[tuple[str, str]] = set()
    for row in baseline:
        if isinstance(row, dict):
            flagged.add((str(row.get("event_id", "")), str(row.get("owasp_category", ""))))
    return flagged


def _user_content(payload: list[dict[str, str]], already: set[tuple[str, str]]) -> str:
    import json

    return json.dumps(
        {
            "events": payload,
            "already_flagged": [{"event_id": eid, "owasp_category": cat} for eid, cat in sorted(already)],
        },
        ensure_ascii=False,
    )


def _validate_findings(
    findings: Any,
    payload: list[dict[str, str]],
    already: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    if not isinstance(findings, list):
        return []
    valid_event_ids = {row["event_id"] for row in payload}
    seen: set[tuple[str, str]] = set()
    rows: list[dict[str, Any]] = []
    for row in findings:
        if not isinstance(row, dict):
            continue
        event_id = str(row.get("event_id", ""))
        category = str(row.get("owasp_category", ""))
        if event_id not in valid_event_ids or category not in OWASP_CATEGORIES:
            continue
        key = (event_id, category)
        if key in already or key in seen:
            continue
        confidence = row.get("confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            continue
        seen.add(key)
        rows.append(
            {
                "event_id": event_id,
                "owasp_category": category,
                "confidence": round(max(0.0, min(1.0, float(confidence))), 2),
                "signals": ["llm_assessment"],
                "source": "llm",
                "rationale": mask_sensitive(str(row.get("rationale", "")))[:_MAX_RATIONALE_CHARS],
            }
        )
    return rows
