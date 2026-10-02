"""Internal helpers shared by CMN-C1-197 services.

Utilities only (not part of the node contract). Kept deterministic and
side-effect free so service logic stays testable without any external service
or unapproved package.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

# ── State JSON (de)serialization (state-safety: see schemas/state.py) ────────
# Structured state fields are stored as JSON strings so the checkpoint holds only
# primitives. Producing slots call ``dump_json`` on write; consuming slots call
# ``load_list`` / ``load_dict`` on read. Readers tolerate an already-parsed
# container (so direct service-level unit tests may pass raw list/dict) and a
# missing / malformed value (degrades to the empty default, never raises).


def dump_json(value: Any) -> Optional[str]:
    """Serialize a state collection to a JSON string. ``None`` stays ``None``."""
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False)


def load_list(value: Any) -> list[Any]:
    """Read a JSON-string (or already-parsed) list state field. Default ``[]``."""
    parsed = _loads_if_str(value)
    return parsed if isinstance(parsed, list) else []


def load_dict(value: Any) -> dict[str, Any]:
    """Read a JSON-string (or already-parsed) dict state field. Default ``{}``."""
    parsed = _loads_if_str(value)
    return parsed if isinstance(parsed, dict) else {}


def _loads_if_str(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return None
    return value


def as_int(value: object, default: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_float(value: object, default: float) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def domain_config(state: dict[str, Any]) -> dict[str, Any]:
    """Return the per-request domain config knobs the caller supplied.

    Domain knobs (policy rules, severity weights, alert format, remediation map,
    thresholds, generated_at) flow through the caller's ``input_context`` — a
    plain JSON-serializable dict on state. Returns ``{}`` when absent or
    malformed so a missing config degrades to "use defaults", never a crash. No
    InvocationContext / credentials are ever carried here.
    """
    if not isinstance(state, dict):
        return {}
    ctx = state.get("input_context")
    return ctx if isinstance(ctx, dict) else {}


# ── S-3 deterministic masking (regex, NOT LLM) ──────────────────────────────
# Sensitive value patterns masked before any alert leaves the agent. These are
# content-value detectors (NOT field-name detectors): the very agent-execution
# logs being classified may embed secrets/PII directly in prompts, tool
# arguments, or responses. Masking is deterministic and idempotent — re-masking
# already-masked text is a no-op.
_MASK = "[REDACTED]"
_SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI-style key
    re.compile(r"eyJ[A-Za-z0-9._\-]{10,}"),  # JWT
    re.compile(r"AKIA[A-Z0-9]{16}"),  # AWS access key
    re.compile(r"(?i)Bearer\s+[A-Za-z0-9._\-]{20,}"),  # bearer token
    re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),  # email
    re.compile(r"\b\d{12}\b"),  # my-number (12 digit)
    re.compile(r"\b(?:\d[ \-]?){13,16}\b"),  # card-like PAN
)


def mask_sensitive(text: Any) -> str:
    """Deterministically mask sensitive substrings in ``text``.

    Returns a string with every sensitive match replaced by ``[REDACTED]``.
    Non-string input is coerced via ``str()``. Pure/deterministic — no LLM,
    no network, idempotent. This is the S-3 enforcement primitive.
    """
    out = text if isinstance(text, str) else str(text)
    for pat in _SENSITIVE_PATTERNS:
        out = pat.sub(_MASK, out)
    return out


def contains_sensitive(text: Any) -> bool:
    """True if any sensitive pattern is present in ``text`` (pre-mask check)."""
    s = text if isinstance(text, str) else str(text)
    return any(pat.search(s) for pat in _SENSITIVE_PATTERNS)
