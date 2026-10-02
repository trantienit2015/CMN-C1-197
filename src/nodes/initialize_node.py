"""InitializeNode — S-1 trust gate + S-2 input validation/normalization.

Overrides the framework default initialize slot. The S-1 trust gate runs in the
framework ``BaseNode.__call__`` *before* ``execute()`` using
``required_trust_level``. Agent execution logs
are internal operational telemetry, so the floor is ``INTERNAL``.

``on_initialize`` performs S-2 input validation: it reads the caller's raw event
batch + log source from ``input_context`` (the framework seeds state with
``user_input`` + ``input_context``), enforces the ``max_events`` ceiling, and
normalizes ``raw_events`` to a JSON string on state (msgpack-safe). On a
validation failure it returns ``status=AgentStatus.ERROR`` + ``error_log`` so the
graph routes straight to finalize and the detection pipeline never runs.

Node contract: overrides ``on_initialize(self, state) -> dict`` only (no
``config`` param, no ``_invoke_impl``, never overrides ``__call__``).
"""

from __future__ import annotations

from typing import Any

from framework.nodes.defaults.initialize_node import InitializeNode as DefaultInitializeNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services._support import as_int, dump_json

# Per-entry input cap (S-2): reject obviously oversized batches early. Deployment
# may override via input_context["max_events"].
DEFAULT_MAX_EVENTS = 100_000


class InitializeNode(DefaultInitializeNode):
    """S-1 trust gate (INTERNAL) + S-2 input validation/normalization."""

    # S-1: agent execution-log access is a privileged, internal-only operation.
    required_trust_level = TrustLevel.INTERNAL

    def on_initialize(self, state: dict[str, Any]) -> dict[str, Any]:
        raw_ctx = state.get("input_context")
        ctx: dict[str, Any] = raw_ctx if isinstance(raw_ctx, dict) else {}

        if not state.get("session_id"):
            return {"status": AgentStatus.ERROR.value, "error_log": ["S-2: missing session_id"]}

        # raw_events: the caller passes a bare list (or JSON string) via
        # input_context; persist it as a JSON string so state holds only
        # primitives (msgpack-safe).
        events = ctx.get("raw_events")
        result: dict[str, Any] = {}
        if isinstance(events, str):
            result["raw_events"] = events
        else:
            entries = events or []
            if not isinstance(entries, list):
                return {
                    "status": AgentStatus.ERROR.value,
                    "error_log": ["S-2: raw_events must be a list or JSON-encoded list"],
                }
            max_events = as_int(ctx.get("max_events"), DEFAULT_MAX_EVENTS)
            if len(entries) > max_events:
                return {
                    "status": AgentStatus.ERROR.value,
                    "error_log": [f"S-2: raw_events exceeds max_events ({max_events})"],
                }
            result["raw_events"] = dump_json(entries)

        result["log_source"] = str(ctx.get("log_source") or "generic")
        if ctx.get("source_agent_id"):
            result["source_agent_id"] = str(ctx.get("source_agent_id"))
        if not state.get("correlation_id"):
            result["correlation_id"] = state.get("session_id")
        result["status"] = AgentStatus.SUCCESS.value
        return result
