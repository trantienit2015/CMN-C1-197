"""tests/test_scaffold.py — CMN-C1-197 scaffold / compliance self-checks.

Real behavioral assertions (not stubs) that verify the recurring the review criteria
this template must satisfy, so every CI run self-verifies compliance:

  * Required deliverable files present.
  * Graph IS the agent and inherits AgentBaseGraph (L1 direct, #10); public
    entry is compile() + invoke(), not run().
  * required_trust_level is a VALID TrustLevel enum — INTERNAL.
  * Slot nodes override execute(); no _invoke_impl / no config param / no
    __call__ override / no .run() in src/ (node contract / #1 / #11).
  * s3_gate_enabled: true in config (security #2).
"""
from __future__ import annotations

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
NODES = SRC / "nodes"


# ── #14 — required committed deliverables present ───────────────────────────
@pytest.mark.parametrize(
    "rel_path",
    [
        "pyproject.toml",
        "README.md",
        "config/agent.yaml",
        "src/graph/graph.py",
        "src/schemas/state.py",
        "src/nodes/initialize_node.py",
        "src/nodes/pre_process_node.py",
        "src/nodes/main_node.py",
        "src/nodes/post_process_node.py",
        "docs/02_design.md",
        "docs/03_test_spec.md",
    ],
)
def test_required_file_exists(rel_path):
    path = REPO_ROOT / rel_path
    assert path.is_file(), f"missing required file: {rel_path}"
    assert path.stat().st_size > 0, f"required file is empty: {rel_path}"


# ── #11 — src/agent.py must NOT exist (graph is the agent) ──────────────────
def test_no_separate_agent_module():
    assert not (SRC / "agent.py").exists(), "src/agent.py must be removed — the graph IS the agent"


# ── #10 — graph IS the agent and inherits AgentBaseGraph (L1 direct) ────────
def test_graph_is_agent_inherits_agent_base_graph():
    from src.graph.graph import Graph, OWASPAnomalyAlertAgent

    assert Graph is OWASPAnomalyAlertAgent
    mro_names = [c.__name__ for c in OWASPAnomalyAlertAgent.__mro__]
    assert "AgentBaseGraph" in mro_names
    for forbidden in ("VectorRAGAgent", "ChatAgent", "DocGenerationAgent", "ReActAgent", "ToolCallingAgent"):
        assert forbidden not in mro_names


# ── #11 — public entry is compile()+invoke(); no .run()/_invoke_impl in src/ ─
def test_no_run_or_invoke_impl_in_src():
    for py in SRC.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        assert not re.search(r"def _invoke_impl", text), f"{py} defines _invoke_impl — framework owns invocation"
        assert not re.search(r"def _security_gate_(input|output)", text), (
            f"{py} defines a developer security gate — framework owns the layers"
        )
        # gate-invoke-chain only forbids a `self.<x>.run(` graph-walk call.
        assert not re.search(r"self\.[_a-z][_a-z0-9]*\.run\(", text), (
            f"{py} calls self.*.run() — use .invoke()"
        )


# ── #11 — slot nodes override execute(self, state) with no config param ─────
def test_slot_nodes_execute_contract():
    for name in ("pre_process_node", "main_node", "post_process_node"):
        text = (NODES / f"{name}.py").read_text(encoding="utf-8")
        # execute(self, state) with no `config` parameter (annotation allowed).
        # The annotation may itself contain a comma (dict[str, Any]), so match up to the
        # closing parenthesis of the parameter list rather than the first comma.
        m = re.search(r"def execute\(self, state(?::\s*[^)]*)?\)", text)
        assert m, f"{name}: execute(self, state) required"
        assert "config" not in m.group(0), f"{name}: execute() must not take a config param"
        assert "def __call__" not in text, f"{name}: must not override __call__"
    # initialize overrides on_initialize (Template-Method extension point)
    init_text = (NODES / "initialize_node.py").read_text(encoding="utf-8")
    assert re.search(r"def on_initialize\(self, state(?::\s*[^)]*)?\)", init_text)


# ── #13 — required_trust_level is a VALID enum value ────────────────────────
def test_required_trust_level_valid_enum():
    from src.nodes.initialize_node import InitializeNode

    name = InitializeNode.required_trust_level.name
    assert name in {"ANONYMOUS", "VERIFIED_EXTERNAL", "INTERNAL"}
    assert name != "VERIFIED_INTERNAL"


# ── security #2 — s3_gate_enabled true ──────────────────────────────────────
def test_s3_gate_enabled_true():
    # Runtime parameters live in config/config.yaml; the manifest carries discovery
    # metadata only, so the gate flag is asserted where it is actually read from.
    runtime_yaml = (REPO_ROOT / "config" / "config.yaml").read_text(encoding="utf-8")
    assert "s3_gate_enabled: true" in runtime_yaml
