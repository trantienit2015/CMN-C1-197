"""Graph composition for CMN-C1-197 — the graph IS the agent.

``OWASPAnomalyAlertAgent`` inherits the L1 ``AgentBaseGraph`` directly (2026-05-18
policy — no Level 2 base agent, no Level 0 ``agenticstar`` import). The graph is
the public, independently-deployable agent: there is no separate agent class and
no ``.run()`` / ``_invoke_impl()`` walk. The public entry is
``Graph().compile()`` then ``.invoke(user_input, ctx=...)`` (framework backbone).

Cat 1 fixed backbone (framework-owned topology):

    initialize → pre_process → main → {route} → post_process → finalize

The architect-spec 6-step OWASP pipeline is mapped onto the slots; the per-step
domain logic lives verbatim in ``src/services/`` (see ``docs/02_design.md``).
``register_nodes()`` calls ``super().register_nodes()`` first (injects the default
initialize + finalize), then fills the three domain slots. ``add_edges()`` /
``route()`` are NOT overridden — the framework owns routing.
"""

from __future__ import annotations

from framework.graph.agent_base_graph import AgentBaseGraph

from src.nodes.initialize_node import InitializeNode
from src.nodes.main_node import MainNode
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.schemas.state import OWASPAlertState


class OWASPAnomalyAlertAgent(AgentBaseGraph):
    """Cat 1 OWASP Agentic runtime anomaly-alert agent — L1 direct, graph = agent."""

    @property
    def name(self) -> str:
        return "OWASPAnomalyAlertAgent"

    @property
    def state_schema(self) -> type:
        return OWASPAlertState

    def register_nodes(self) -> None:
        super().register_nodes()  # injects default initialize + finalize backbone

        # S-1 trust gate (INTERNAL) + S-2 input validation.
        self._nodes["initialize"] = InitializeNode()

        # Domain pipeline slots (required — fill all three):
        self._nodes["pre_process"] = PreProcessNode()  # Step 1 EventStreamParse
        self._nodes["main"] = MainNode()  # Steps 2-5 detect chain
        self._nodes["post_process"] = PostProcessNode()  # Step 6 AuditLogWrite (S-3/S-5)


# Stable alias for the standalone entry point import (src/api/server.py).
# standalone server entry point.
Graph = OWASPAnomalyAlertAgent
