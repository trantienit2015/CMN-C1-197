"""Security gate tests for CMN-C1-197 (S-1 … S-5 + S-3 masking).

Maps to the framework rules TC-02/TC-03/TC-04/TC-05/TC-07/TC-08/TC-13.
"""
from __future__ import annotations

import json

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.nodes.initialize_node import InitializeNode
from src.nodes.post_process_node import PostProcessNode
from src.services._support import contains_sensitive, mask_sensitive
from tests import _fixtures as fx


# ── TC-08 / S-1 — insufficient trust is refused (framework __call__ gate) ───
def test_s1_anonymous_trust_refused():
    out = fx.run([fx.event("e1")], trust=TrustLevel.ANONYMOUS)
    assert out["status"] == AgentStatus.ERROR.value
    assert not out.get("output")  # pipeline never produced an alert


def test_s1_internal_trust_allowed():
    out = fx.run([fx.event("e1")], trust=TrustLevel.INTERNAL)
    assert out["status"] == AgentStatus.SUCCESS.value


# ── TC-13 / S-1 — required_trust_level is a VALID enum (criterion #13) ──────
def test_s1_required_trust_level_is_valid_enum():
    name = InitializeNode.required_trust_level.name
    assert name == "INTERNAL"
    assert name in {"ANONYMOUS", "VERIFIED_EXTERNAL", "INTERNAL"}
    assert name != "VERIFIED_INTERNAL"


# ── TC-02 / S-2 — missing session_id sets a validation error (status ERROR) ─
def test_s2_missing_session_id():
    node = InitializeNode()
    out = node.on_initialize({"session_id": "", "input_context": {"raw_events": []}})
    assert out["status"] == AgentStatus.ERROR.value
    assert any("session_id" in e for e in out["error_log"])


# ── S-2 — oversized batch is rejected (status ERROR) ────────────────────────
def test_s2_oversized_batch_rejected():
    node = InitializeNode()
    out = node.on_initialize(
        {"session_id": "s", "input_context": {"raw_events": [fx.event("e")] * 5, "max_events": 2}}
    )
    assert out["status"] == AgentStatus.ERROR.value
    assert any("max_events" in e for e in out["error_log"])


# ── TC-07 / S-3 — sensitive values are masked deterministically ─────────────
def test_s3_masking_redacts_secrets():
    secret = "contact me at agent@example.com or use sk-ABCDEFGHIJKLMNOPQRSTUVWX"
    masked = mask_sensitive(secret)
    assert "agent@example.com" not in masked
    assert "sk-ABCDEFGHIJKLMNOPQRSTUVWX" not in masked
    assert "[REDACTED]" in masked
    assert mask_sensitive(masked) == masked  # idempotent


def test_s3_post_process_masks_alert_with_embedded_secret():
    payload = {
        "alert_id": "a1", "format": "generic",
        "summary": {"total_violations": 1},
        "findings": [{"event_id": "e", "note": "token sk-ABCDEFGHIJKLMNOPQRSTUVWX"}],
    }
    state = {"session_id": "s", "alert_payload": json.dumps(payload), "input_context": {"generated_at": "t"}}
    out = PostProcessNode().execute(state)
    assert "sk-ABCDEFGHIJKLMNOPQRSTUVWX" not in out["masked_alert"]
    assert out["status"] == AgentStatus.SUCCESS.value
    assert contains_sensitive(json.dumps(payload)) is True


# ── TC-05 / S-4 / S-5 — audit entry emitted on success path ─────────────────
def test_s5_audit_log_present_on_success():
    state = fx.domain_state([fx.injection_event("e1")])
    from src.nodes.main_node import MainNode
    from src.nodes.pre_process_node import PreProcessNode

    state.update(PreProcessNode().execute(state))
    state.update(MainNode().execute(state))
    out = PostProcessNode().execute(state)
    audit = json.loads(out["audit_log_entry"])
    assert audit["template_id"] == "CMN-C1-197"
    assert audit["status"] == "success"
    assert audit["s3_masked"] is True


# ── S-5 — audit still emitted when the pipeline halts (no un-audited exit) ──
def test_s5_audit_log_present_on_halt():
    out = PostProcessNode().execute(
        {"session_id": "s", "status": AgentStatus.ERROR.value, "input_context": {}}
    )
    audit = json.loads(out["audit_log_entry"])
    assert audit["status"] == "halted"


# ── TC-04 / state safety — post-invoke state holds only primitives ──────────
def test_tc04_returned_state_is_primitive_only():
    out = fx.run([fx.event("e1")])
    for key, value in out.items():
        assert isinstance(value, (str, int, float, bool, type(None), list, dict)), (
            f"non-primitive state field {key!r}: {type(value)}"
        )
    json.dumps(out)  # whole output is JSON round-trippable (msgpack-safe proxy)


# ── TC-03 — a JWT-shaped value that reaches a caller-facing field is redacted
def test_tc03_jwt_in_alert_is_masked_out():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9payload"
    masked = mask_sensitive(f"token={jwt}")
    assert jwt not in masked
    assert "[REDACTED]" in masked
