"""Unit tests for InitializeNode (S-1 declaration + S-2 validation)."""
from __future__ import annotations

import json

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.nodes.initialize_node import InitializeNode
from tests import _fixtures as fx


def test_initialize_requires_internal_trust():
    assert InitializeNode.required_trust_level == TrustLevel.INTERNAL


def test_initialize_accepts_json_string_raw_events():
    node = InitializeNode()
    raw = json.dumps([fx.event("e1")])
    out = node.on_initialize({"session_id": "s", "input_context": {"raw_events": raw}})
    assert out["status"] == AgentStatus.SUCCESS.value
    assert out["raw_events"] == raw
    assert out["log_source"] == "generic"  # default applied


def test_initialize_rejects_non_list_raw_events():
    node = InitializeNode()
    out = node.on_initialize({"session_id": "s", "input_context": {"raw_events": 42}})
    assert out["status"] == AgentStatus.ERROR.value
    assert any("list" in e for e in out["error_log"])


def test_initialize_seeds_correlation_id_from_session():
    node = InitializeNode()
    out = node.on_initialize({"session_id": "sid-1", "input_context": {"raw_events": []}})
    assert out["correlation_id"] == "sid-1"
