"""Tests for the OPTIONAL LLM enhancement of Step 2 classification (see
docs/02_design.md §3) — ``src/services/llm_classify_service.py``.

All tests use a fake LLM test-double (``complete(messages) -> {"content": ...}``)
injected via ``MainNode(llm=...)`` or passed directly to ``enhance()`` — no real
network call anywhere in this suite (the template's own "no unapproved package"
default).
"""
from __future__ import annotations

import json

import pytest

from framework.schemas.agent_status import AgentStatus

from src.nodes.main_node import MainNode
from src.nodes.pre_process_node import PreProcessNode
from src.services import llm_classify_service as llm_svc
from src.services import owasp_classify_service as classify_svc
from tests import _fixtures as fx


class FakeLLM:
    """Minimal BaseLLM-shaped test double — no network, no real client."""

    def __init__(self, content: str | None = None, raises: bool = False):
        self._content = content
        self._raises = raises
        self.calls: list[list[dict]] = []

    def complete(self, messages: list) -> dict:
        self.calls.append(messages)
        if self._raises:
            raise RuntimeError("simulated API error")
        return {"content": self._content}


_EVENTS = [{"event_id": "e1", "prompt": "totally benign", "response": "ok", "action_type": "", "tools": []}]
_STATE = {"parsed_events": json.dumps(_EVENTS)}


# ── enhance() unit tests ─────────────────────────────────────────────────────


def test_llm_adds_a_finding_the_rule_table_missed():
    baseline: list[dict] = []  # rule table found nothing
    reply = json.dumps(
        {
            "findings": [
                {
                    "event_id": "e1",
                    "owasp_category": "model_denial_of_service",
                    "confidence": 0.9,
                    "rationale": "unbounded loop pattern in tool trace",
                }
            ]
        }
    )
    llm = FakeLLM(content=reply)
    rows = llm_svc.enhance(_EVENTS, baseline, llm, _STATE)
    assert rows is not None
    assert rows[0]["owasp_category"] == "model_denial_of_service"
    assert rows[0]["source"] == "llm"
    assert 0.0 <= rows[0]["confidence"] <= 1.0


def test_llm_reply_wrapped_in_prose_and_markdown_fence_still_parses():
    reply = (
        "Here is my analysis:\n```json\n"
        + json.dumps({"findings": [{"event_id": "e1", "owasp_category": "cascading_failures", "confidence": 0.6}]})
        + "\n```\nLet me know if you need more detail."
    )
    llm = FakeLLM(content=reply)
    rows = llm_svc.enhance(_EVENTS, [], llm, _STATE)
    assert rows is not None
    assert rows[0]["owasp_category"] == "cascading_failures"


def test_malformed_response_falls_back_to_heuristic():
    llm = FakeLLM(content="not json at all, sorry")
    rows = llm_svc.enhance(_EVENTS, [{"event_id": "e1", "owasp_category": "prompt_injection", "confidence": 0.5}], llm, _STATE)
    assert rows is None


def test_wrong_shape_response_falls_back_to_heuristic():
    # "findings" present but not a list.
    llm = FakeLLM(content=json.dumps({"findings": "not-a-list"}))
    assert llm_svc.enhance(_EVENTS, [], llm, _STATE) is None


def test_unknown_category_and_unknown_event_id_are_dropped_not_fatal():
    reply = json.dumps(
        {
            "findings": [
                {"event_id": "e1", "owasp_category": "not_a_real_category", "confidence": 0.9},
                {"event_id": "does-not-exist", "owasp_category": "supply_chain", "confidence": 0.9},
            ]
        }
    )
    llm = FakeLLM(content=reply)
    assert llm_svc.enhance(_EVENTS, [], llm, _STATE) is None  # both rows invalid -> no rows -> None


def test_already_flagged_pair_is_not_duplicated():
    baseline = [{"event_id": "e1", "owasp_category": "supply_chain", "confidence": 0.5}]
    reply = json.dumps({"findings": [{"event_id": "e1", "owasp_category": "supply_chain", "confidence": 0.99}]})
    llm = FakeLLM(content=reply)
    assert llm_svc.enhance(_EVENTS, baseline, llm, _STATE) is None  # only dup offered -> no new rows


def test_llm_raising_falls_back_to_heuristic():
    llm = FakeLLM(raises=True)
    assert llm_svc.enhance(_EVENTS, [], llm, _STATE) is None


def test_no_events_never_calls_the_llm():
    llm = FakeLLM(content=json.dumps({"findings": []}))
    assert llm_svc.enhance([], [], llm, _STATE) is None
    assert llm.calls == []  # never invoked


def test_no_llm_injected_and_no_secret_bound_falls_back_to_heuristic():
    # llm=None and no InvocationContext-resolvable secrets in this bare state.
    assert llm_svc.enhance(_EVENTS, [], None, _STATE) is None


# ── MainNode wiring tests (through the real pipeline) ───────────────────────


def test_main_node_merges_llm_rows_into_the_pipeline():
    reply = json.dumps(
        {"findings": [{"event_id": "e1", "owasp_category": "repudiation_audit_gaps", "confidence": 0.8}]}
    )
    node = MainNode(llm=FakeLLM(content=reply))
    state = fx.domain_state([fx.event("e1", prompt="benign", response="benign")])
    state.update(PreProcessNode().execute(state))
    out = node.execute(state)
    assert out["status"] == AgentStatus.SUCCESS.value
    classifications = json.loads(out["owasp_classifications"])
    assert any(c["owasp_category"] == "repudiation_audit_gaps" and c["source"] == "llm" for c in classifications)


def test_main_node_with_raising_llm_still_succeeds_on_rule_table_alone():
    node = MainNode(llm=FakeLLM(raises=True))
    state = fx.domain_state([fx.injection_event("e1")])
    state.update(PreProcessNode().execute(state))
    out = node.execute(state)
    assert out["status"] == AgentStatus.SUCCESS.value
    classifications = json.loads(out["owasp_classifications"])
    assert any(c["owasp_category"] == "prompt_injection" for c in classifications)
    assert all(c.get("source") != "llm" for c in classifications)


def test_main_node_default_construction_has_no_llm_and_stays_deterministic():
    # register_nodes() never passes an llm= — this is the production wiring path.
    node = MainNode()
    assert node._llm is None
    state = fx.domain_state([fx.injection_event("e1")])
    state.update(PreProcessNode().execute(state))
    out1 = node.execute(dict(state))
    out2 = node.execute(dict(state))
    assert out1["owasp_classifications"] == out2["owasp_classifications"]  # reproducible, no LLM reached
