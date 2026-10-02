"""PreProcessNode — Step 1/6: cross-provider log normalization (EventStreamParse).

Reads the validated ``raw_events`` (JSON string) + ``log_source`` from state and
delegates to ``event_stream_parse_service.parse_events`` — the full per-provider
(Azure/AWS/GCP/generic) adapter + S-1 normalization (HTML strip + per-field
truncation). On an upstream validation halt (``status == ERROR``) the slot is a
no-op so the pipeline short-circuits to finalize.

Node contract: overrides ``execute(self, state) -> dict`` only (no ``config``
param). Returns a partial update with an ``AgentStatus.*`` enum status.
"""

from __future__ import annotations

from typing import Any

from framework.nodes.function_node import FunctionNode
from shared.utils.audit_logger import emit_trace_event
from shared.services.events import emitter
from shared.services.events.types import EventType
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services import event_stream_parse_service as parse_svc
from src.services._support import as_int, domain_config, dump_json, load_list


class PreProcessNode(FunctionNode):
    """Step 1 — cross-provider log normalization + S-1 input sanitization."""

    # S-1 (criterion #13): agent execution logs are internal operational
    # telemetry — same floor as InitializeNode and agent.yaml. Declared
    # explicitly; implicit ANONYMOUS inheritance is not acceptable.
    required_trust_level = TrustLevel.INTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Progress (non-terminal) event for the caller. Outside the Marketplace runtime
        # this resolves to a no-op emitter, so it is safe on every entry path.
        emitter().emit_event(
            event_type=EventType.PROGRESS_UPDATE,
            message="Checking the request...",
            metadata={"step": "pre_process"},
        )
        if state.get("status") == AgentStatus.ERROR.value:
            return {}  # upstream halt — short-circuit, preserve ERROR

        cfg = domain_config(state)
        max_chars = as_int(cfg.get("max_field_chars"), parse_svc.DEFAULT_MAX_FIELD_CHARS)

        raw = load_list(state.get("raw_events"))
        parsed = parse_svc.parse_events(raw, state.get("log_source") or "generic", max_chars)
        emit_trace_event(
            "runtime_event_parse",
            {"parsed_events": len(parsed), "log_source": state.get("log_source") or "generic"},
            state,
        )
        return {"parsed_events": dump_json(parsed), "status": AgentStatus.SUCCESS.value}
