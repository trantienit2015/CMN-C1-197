"""Standalone HTTP entry point for CMN-C1-197 (adapter only — no business logic).

For platform-level routing, AgentGateway compiles the graph and calls
``agent.invoke(user_input, ctx=...)``. This FastAPI shim exists so the agent can
also be exercised as a standalone endpoint. It builds the ``input_context`` from
the request and delegates to the same public entry the gateway uses
(``Graph().compile()`` + ``.invoke(..., ctx=...)``) — never ``.run()``
(review criterion #11).

Secrets (S-3) are provisioned once at startup via ``provision_secrets`` +
``secrets_factory`` and bound per request with ``bound_secrets`` — never read from
``os.environ`` and never stored in state. (This template's detection logic is
fully deterministic and needs no secret today; the provider is wired so the
standard S-3 mechanism is in place if a future external sink is added.)

Caller authentication is the entry-point auth boundary (standalone equivalent of
the platform AuthMiddleware): ``INVOKE_AUTH_TOKEN`` is a deployment-level caller
credential read from the process environment by design — it authenticates the
caller *before* any ``InvocationContext`` exists, so ``ctx.secrets`` cannot apply
(the framework rules).
"""

from __future__ import annotations

import os
import secrets as _secrets
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml
from langgraph.checkpoint.memory import MemorySaver

try:
    from fastapi import FastAPI, HTTPException, Request
    from pydantic import BaseModel
except ImportError:  # pragma: no cover - FastAPI is a deployment-only dependency
    FastAPI = None  # type: ignore[assignment,misc]
    HTTPException = None  # type: ignore[assignment,misc]
    Request = None  # type: ignore[assignment,misc]
    BaseModel = object  # type: ignore[assignment,misc]

from framework.schemas.invocation_context import InvocationContext, TrustLevel
from framework.secrets.context import bound_secrets
from shared.secrets import factory as secrets_factory

from src.graph.graph import Graph

_NAMESPACE = "cmn-c1-197"
_AGENT_NAME = "OWASPAnomalyAlertAgent"

# Runtime config, same config_dir / "config.yaml" convention AgentRegistry uses;
# an absent file is tolerated and yields {}. Without this the standalone entry point
# constructed the graph with no config at all, so no runtime parameter reached it on
# this path.
_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"
_config = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {} if _CONFIG_PATH.exists() else {}

agent = Graph(config=_config)
# memory_enabled / hitl.enabled need a checkpointer, or memory and interrupt()
# silently no-op on this path.
_hitl_enabled = agent.config.get("hitl", {}).get("enabled", False)
_needs_checkpointer = agent.config.get("memory_enabled") or _hitl_enabled
agent.compile(checkpointer=MemorySaver() if _needs_checkpointer else None)
agent.provision_secrets(secrets_factory(namespace=_NAMESPACE, agent_name=_AGENT_NAME))

# The manifest's own required_trust_level is the ceiling this entry point can ever
# grant a caller that only proved possession of INVOKE_AUTH_TOKEN (see below) — read
# once at import time so a bearer-verified caller is trusted to exactly what this
# agent's own boundary nodes already require, no more and no less.
# Resolved relative to this file, not the process cwd: the manifest must load
# identically whether uvicorn is started from the repo root (CI deploy-stg) or
# from elsewhere, so the granted trust ceiling can never silently differ.
_MANIFEST_PATH = Path(__file__).resolve().parents[2] / "config" / "agent.yaml"
_MANIFEST_TRUST_LEVEL = TrustLevel(yaml.safe_load(_MANIFEST_PATH.read_text(encoding="utf-8"))["required_trust_level"])


if FastAPI is not None:  # pragma: no cover - exercised only in a deployed environment
    app = FastAPI(title="CMN-C1-197 OWASP Agentic Runtime Anomaly Alert Agent")

    class InvokeRequest(BaseModel):
        session_id: str = ""
        log_source: str = "generic"
        raw_events: list[Any] = []
        configurable: dict[str, Any] = {}

    _TRUST_ORDER = (TrustLevel.ANONYMOUS, TrustLevel.VERIFIED_EXTERNAL, TrustLevel.INTERNAL)

    def _capped(level: TrustLevel) -> TrustLevel:
        """Never grant more than this agent's own manifest level."""
        if _TRUST_ORDER.index(level) <= _TRUST_ORDER.index(_MANIFEST_TRUST_LEVEL):
            return level
        return _MANIFEST_TRUST_LEVEL

    def _bearer_matches(supplied: str, expected: str) -> bool:
        """Constant-time bearer comparison that is safe for non-ASCII header input."""
        # Compare bytes: compare_digest raises TypeError on non-ASCII str input
        # (headers decode as latin-1), which would 500 instead of the generic 401.
        return _secrets.compare_digest(supplied.encode(), f"Bearer {expected}".encode())

    def _resolve_standalone_trust(
        current: TrustLevel, authorization: str, invoke_auth_token: Any, internal_runner_token: Any
    ) -> TrustLevel:
        """Authenticate standalone callers without allowing external-token elevation.

        The STG runner credential is a separate, CI-generated deployment credential: it is
        considered only for an anonymous caller and maps to INTERNAL, while the external
        token stays at VERIFIED_EXTERNAL. Both are capped by this agent's manifest level,
        and middleware-established trust is never changed.
        """
        if current is not TrustLevel.ANONYMOUS:
            return current
        if internal_runner_token and _bearer_matches(authorization, internal_runner_token):
            return _capped(TrustLevel.INTERNAL)
        if invoke_auth_token and _bearer_matches(authorization, invoke_auth_token):
            return _capped(TrustLevel.VERIFIED_EXTERNAL)
        if internal_runner_token or invoke_auth_token:
            # Generic body on purpose — do not leak whether the token was absent,
            # malformed, or wrong.
            raise HTTPException(status_code=401, detail="Token is invalid or expired.")
        return TrustLevel.ANONYMOUS

    @app.post("/invoke")
    async def invoke(req: "InvokeRequest", request: Request) -> Any:
        session_id = req.session_id or str(uuid4())
        input_context: dict[str, Any] = {
            "raw_events": req.raw_events,
            "log_source": req.log_source,
            **(req.configurable or {}),
        }

        # This adapter is the entry-point auth boundary (the standalone equivalent of the
        # platform auth middleware). Both values are deployment-level caller credentials,
        # not agent secrets: no InvocationContext exists before this boundary, so
        # ctx.secrets cannot apply. Reaching this agent's own INTERNAL requirement needs
        # the separate STG runner credential; the external token never elevates that far.
        trust = _resolve_standalone_trust(
            getattr(request.state, "trust_level", TrustLevel.ANONYMOUS),
            request.headers.get("authorization", ""),
            os.environ.get("INVOKE_AUTH_TOKEN"),
            os.environ.get("STG_INTERNAL_RUNNER_TOKEN"),
        )

        ctx = InvocationContext(
            session_id=session_id,
            caller_trust_level=trust,
            caller_id=getattr(request.state, "caller_id", ""),
        )
        with bound_secrets(agent._secrets_provider):
            result = agent.invoke("", session_id=session_id, ctx=ctx, input_context=input_context)
        # The graph contract returns a mapping. Verify it at the boundary instead
        # of declaring the shape and trusting it: an unexpected result would
        # otherwise reach the caller as a malformed body.
        if not isinstance(result, dict):
            raise HTTPException(status_code=500, detail="Agent returned an unexpected result shape.")
        return result

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "agent": "CMN-C1-197"}
