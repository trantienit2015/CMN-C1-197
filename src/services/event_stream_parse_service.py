"""EventStreamParse service (Step 1/6 — domain logic for the pre_process slot).

Normalizes raw AI agent execution logs across cloud / agent-framework formats
(Azure, AWS, GCP, generic) into a canonical event schema, and applies S-1 input
normalization (HTML strip + per-field size truncation). S-1 is normalization
only — injection *blocking* is the S-3 gate's job, not asserted here.

Produces a list of normalized events
``[{event_id, agent_id, action_type, model, prompt, tools, response,
session_id, ts}]``.

Deterministic, side-effect free, no external service / LLM. Logic preserved
1:1 from the architect-spec EventStreamParse node.
"""

from __future__ import annotations

import re
from typing import Any

# Per-field text cap (S-1 truncation; deployment may override via config
# "max_field_chars"). Keeps state bounded and msgpack-light.
DEFAULT_MAX_FIELD_CHARS = 2000
_HTML_TAG = re.compile(r"<[^>]+>")
_SUPPORTED_SOURCES = {"azure", "aws", "gcp", "generic"}


def parse_events(raw: list[Any], log_source: str, max_chars: int = DEFAULT_MAX_FIELD_CHARS) -> list[dict[str, Any]]:
    """Normalize a batch of raw provider log entries to the canonical schema."""
    source = str(log_source or "generic").strip().lower()
    if source not in _SUPPORTED_SOURCES:
        source = "generic"

    if not raw:
        # An empty batch is a *valid* empty result (produces a clean report
        # downstream), not an error.
        return []

    parsed: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        parsed.append(_normalize(source, idx, entry, max_chars))
    return parsed


def _normalize(source: str, idx: int, entry: dict[str, Any], max_chars: int) -> dict[str, Any]:
    """Map a provider-specific log entry onto the canonical event schema.

    Providers differ in field naming for the same concepts:
      azure    : {"operationName", "properties.model", "properties.input", ...}
      aws       : {"eventName", "requestParameters", "responseElements", ...}
      gcp       : {"methodName", "request", "response", ...}
      generic   : best-effort across the canonical keys
    """
    event_id = entry.get("event_id") or entry.get("id") or f"ev{idx}"

    if source == "azure":
        action_type = entry.get("operationName", entry.get("action_type"))
        model = entry.get("model", _dig(entry, "properties", "model"))
        prompt = entry.get("prompt", _dig(entry, "properties", "input"))
        response = entry.get("response", _dig(entry, "properties", "output"))
        tools = entry.get("tools", _dig(entry, "properties", "tools"))
    elif source == "aws":
        action_type = entry.get("eventName", entry.get("action_type"))
        model = entry.get("model", entry.get("modelId"))
        prompt = entry.get("prompt", entry.get("requestParameters"))
        response = entry.get("response", entry.get("responseElements"))
        tools = entry.get("tools", entry.get("toolCalls"))
    elif source == "gcp":
        action_type = entry.get("methodName", entry.get("action_type"))
        model = entry.get("model", entry.get("modelName"))
        prompt = entry.get("prompt", entry.get("request"))
        response = entry.get("response", entry.get("responseBody"))
        tools = entry.get("tools", entry.get("toolInvocations"))
    else:  # generic
        action_type = entry.get("action_type", entry.get("action"))
        model = entry.get("model")
        prompt = entry.get("prompt", entry.get("input"))
        response = entry.get("response", entry.get("output"))
        tools = entry.get("tools", entry.get("tool_calls"))

    return {
        "event_id": str(event_id),
        "agent_id": str(entry.get("agent_id") or entry.get("source_agent_id") or "unknown"),
        "action_type": _sanitize_text(action_type, max_chars),
        "model": _sanitize_text(model, max_chars),
        "prompt": _sanitize_text(prompt, max_chars),
        "response": _sanitize_text(response, max_chars),
        "tools": _sanitize_tools(tools, max_chars),
        "session_id": str(entry.get("session_id") or ""),
        "ts": str(entry.get("ts") or entry.get("timestamp") or ""),
    }


def _sanitize_tools(value: object, max_chars: int) -> list[Any]:
    """Normalize the tools field to a list of sanitized tool-name strings."""
    if isinstance(value, list):
        return [_sanitize_text(v, max_chars) for v in value]
    if value is None:
        return []
    return [_sanitize_text(value, max_chars)]


def _sanitize_text(value: object, max_chars: int) -> str:
    """S-1 normalization: HTML strip + truncate. No injection *blocking*."""
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    text = _HTML_TAG.sub("", text)
    if len(text) > max_chars:
        text = text[:max_chars]
    return text


def _dig(entry: dict[str, Any], *keys: str) -> object:
    """Walk nested dicts (best-effort) returning None if any key is missing."""
    cur: object = entry
    for key in keys:
        if isinstance(cur, dict):
            cur = cur.get(key)
        else:
            return None
    return cur
