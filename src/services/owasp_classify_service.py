"""OWASPTaxonomyClassify service (Step 2/6 — domain logic for the main slot).

Classifies each parsed event against the OWASP Agentic Top 10 taxonomy using a
**deterministic, rule-based** signal matcher — NOT LLM inference (S-3 output
gate keeps the result reproducible). Each OWASP category is described by a set of
signal patterns (regex over the prompt / response / tool fields plus structural
heuristics such as tool-call volume); a match records the category with a
confidence proportional to the number of distinct signals fired.

Categories (OWASP Agentic Top 10, abbreviated keys):
  ASI01 prompt_injection           ASI06 excessive_agency
  ASI02 sensitive_info_disclosure  ASI07 privilege_escalation
  ASI03 insecure_output_handling   ASI08 session_hijacking
  ASI04 model_denial_of_service    ASI09 repudiation_audit_gaps
  ASI05 supply_chain               ASI10 cascading_failures

Produces a list ``[{event_id, owasp_category, confidence, signals}]`` (one row
per matched category per event; events with no match contribute nothing).

Deterministic, no LLM, no network. Logic preserved 1:1 from the architect-spec
OWASPTaxonomyClassify node.
"""

from __future__ import annotations

import re
from typing import Any

# Default excessive-agency / DoS thresholds (deployment may override via config).
DEFAULT_MAX_TOOL_CALLS = 10

# Deterministic OWASP Agentic Top 10 signal table. Each entry maps a category to
# regex signals checked against the concatenated prompt/response/tools text. This
# is a transparent rule table (NO LLM), keeping the classifier reproducible and
# auditable — the detail signatures follow OWASP Agentic Top 10 guidance.
_SIGNALS: dict[str, tuple[re.Pattern[str], ...]] = {
    "prompt_injection": (
        re.compile(r"(?i)ignore (?:all |the )?(?:previous|prior|above) (?:instructions|prompts)"),
        re.compile(r"(?i)disregard (?:your|the) (?:system|safety) (?:prompt|rules)"),
        re.compile(r"(?i)you are now (?:in )?(?:dan|developer mode|jailbreak)"),
        re.compile(r"(?i)reveal (?:your |the )?system prompt"),
    ),
    "sensitive_info_disclosure": (
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
        re.compile(r"eyJ[A-Za-z0-9._\-]{10,}"),
        re.compile(r"(?i)(?:api[_ -]?key|secret|password|credential)\s*[:=]"),
    ),
    "insecure_output_handling": (
        re.compile(r"(?i)<script\b"),
        re.compile(r"(?i)(?:rm -rf|drop table|;\s*delete from)"),
        re.compile(r"(?i)\$\((?:.|\n)*\)|`[^`]+`"),  # shell substitution echoed back
    ),
    "privilege_escalation": (
        re.compile(r"(?i)\b(?:sudo|setuid|chmod 777|grant all privileges)\b"),
        re.compile(r"(?i)assume (?:the )?(?:admin|root|superuser) role"),
        re.compile(r"(?i)escalate (?:to )?(?:admin|root|privileged)"),
    ),
    "session_hijacking": (
        re.compile(r"(?i)(?:session[_ -]?token|jsessionid|sid)\s*[:=]"),
        re.compile(r"(?i)reuse (?:the )?(?:other|another) (?:user'?s )?session"),
        re.compile(r"(?i)impersonate (?:user|account)"),
    ),
    "supply_chain": (
        re.compile(r"(?i)pip install (?:--index-url|http://)"),
        re.compile(r"(?i)(?:curl|wget)\s+http[s]?://\S+\s*\|\s*(?:sh|bash)"),
    ),
}


def classify(events: list[Any], max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS) -> list[dict[str, Any]]:
    """Classify parsed events against the OWASP Agentic Top 10 signal table."""
    classifications: list[dict[str, Any]] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        haystack = _haystack(ev)
        for category, patterns in _SIGNALS.items():
            fired = [p.pattern for p in patterns if p.search(haystack)]
            if fired:
                classifications.append(_row(ev, category, fired, len(patterns)))

        # Structural heuristics (not regex): excessive agency / DoS by volume.
        tool_count = len(ev.get("tools") or [])
        if tool_count > max_tool_calls:
            classifications.append(_row(ev, "excessive_agency", [f"tool_calls={tool_count}>{max_tool_calls}"], 1))
    return classifications


def _haystack(ev: dict[str, Any]) -> str:
    parts = [
        str(ev.get("prompt", "")),
        str(ev.get("response", "")),
        str(ev.get("action_type", "")),
        " ".join(str(t) for t in (ev.get("tools") or [])),
    ]
    return "\n".join(parts)


def _row(ev: dict[str, Any], category: str, signals: list[str], total_signals: int) -> dict[str, Any]:
    # Confidence = fraction of the category's signal set that fired, clamped
    # to [0.34, 1.0] so a single deterministic hit is never below "low".
    confidence = round(max(0.34, min(1.0, len(signals) / max(1, total_signals))), 2)
    return {
        "event_id": str(ev.get("event_id", "")),
        "owasp_category": category,
        "confidence": confidence,
        "signals": signals,
    }
