"""PolicyViolationDetect service (Step 3/6 — domain logic for the main slot).

Decides which OWASP classifications constitute *actual* policy violations by
applying configurable policy rules. The policy is config-driven (Cat 1 = zero
domain assumption): a deployment supplies, via the caller's ``input_context``:

  * ``policy_min_confidence`` — minimum classifier confidence for a
    classification to count as a violation (default 0.5).
  * ``policy_enabled_categories`` — optional allowlist of OWASP categories the
    organization monitors; when absent, ALL categories are in scope.
  * ``policy_rules`` — optional list of ``{category, min_confidence, rule_id}``
    overrides applied per category.

No OWASP category list is hardcoded as "always a violation" — the template stays
industry-agnostic and the organization's policy lives entirely in config.

Produces a list ``[{event_id, owasp_category, rule_id, confidence,
is_violation}]`` (only the rows that ARE violations are emitted).

Deterministic. Logic preserved 1:1 from the architect-spec PolicyViolationDetect
node.
"""

from __future__ import annotations

from typing import Any

from src.services._support import as_float

DEFAULT_MIN_CONFIDENCE = 0.5


def detect(
    classifications: list[Any],
    policy_min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    policy_enabled_categories: object = None,
    policy_rules: object = None,
) -> list[dict[str, Any]]:
    """Evaluate config-driven policy rules over OWASP classifications."""
    default_min = as_float(policy_min_confidence, DEFAULT_MIN_CONFIDENCE)
    enabled_set = (
        set(policy_enabled_categories)
        if isinstance(policy_enabled_categories, list) and policy_enabled_categories
        else None
    )
    per_category = _index_rules(policy_rules)

    violations: list[dict[str, Any]] = []
    for c in classifications:
        if not isinstance(c, dict):
            continue
        category = str(c.get("owasp_category", ""))
        if enabled_set is not None and category not in enabled_set:
            continue
        rule = per_category.get(category, {})
        min_conf = as_float(rule.get("min_confidence"), default_min)
        rule_id = str(rule.get("rule_id") or f"policy:{category}")
        confidence = as_float(c.get("confidence"), 0.0)
        if confidence >= min_conf:
            violations.append(
                {
                    "event_id": str(c.get("event_id", "")),
                    "owasp_category": category,
                    "rule_id": rule_id,
                    "confidence": confidence,
                    "is_violation": True,
                }
            )
    return violations


def _index_rules(rules: object) -> dict[str, Any]:
    """Index config ``policy_rules`` by category. Tolerant of malformed config."""
    index: dict[str, Any] = {}
    if isinstance(rules, list):
        for r in rules:
            if isinstance(r, dict) and r.get("category"):
                index[str(r["category"])] = r
    return index
