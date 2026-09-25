"""AgentCore Platform v1.0"""

# Standalone HTTP entry point for the agent.
# Entry points are adapters only — no business logic here.
# For platform-level routing, AgentGateway calls agent.invoke() directly.

from typing import Any
import logging
import os
import secrets
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from langgraph.checkpoint.memory import MemorySaver
from pydantic import BaseModel

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from framework.secrets.context import bound_secrets
from framework.utils.config_loader import load_config
from shared.secrets import factory as secrets_factory
from src.graph.graph import Graph
from src.services.deploy_adapter import build_baseline_store, build_dispatcher

app = FastAPI(title="Agent")

# Same config_dir / "config.yaml" convention as AgentRegistry._compile_and_cache()
# (mediator/registry/agent_registry.py) — absent config.yaml is tolerated, matching
# the registry's own `if exists() else {}` guard. Without this, the standalone
# adapter always ran with config={}, so hitl.enabled / memory_enabled / max_retry
# etc. silently never reached Graph() on this path.
_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"
_config = load_config(str(_CONFIG_PATH)) if _CONFIG_PATH.exists() else {}


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")


# Production wiring: the rolling-baseline store and the alert dispatcher are built from
# the declared secrets (BASELINE_STORE_API_KEY / BASELINE_STORE_URL / ALERT_DISPATCH_TOKEN);
# a missing resource aborts boot (fail-closed). The stand-in (empty baseline, so every zone
# scores NORMAL; no dispatcher, so alerts are only 'queued') is selected only by an explicit
# non-production signal:
#   - STG_MOCK_MODE=true: set by the CI deploy-stg job (in-job deploy with no real secrets
#     and no egress), so its evidence proves the deterministic pipeline, not live delivery;
#   - RET_C2_287_ALLOW_STUB_DEPLOY=1: explicit demo/local opt-in.
_allow_stub = _flag("STG_MOCK_MODE") or _flag("RET_C2_287_ALLOW_STUB_DEPLOY")
if _allow_stub:
    logging.getLogger(__name__).warning(
        "Non-production stand-in active: empty baseline and no alert dispatcher are wired."
    )

_secrets_provider = secrets_factory(namespace="ret", agent_name="ret-c2-287")
with bound_secrets(_secrets_provider):
    _config["baseline_store"] = build_baseline_store(_secrets_provider, allow_stub=_allow_stub)
    _config["dispatcher"] = build_dispatcher(_secrets_provider, allow_stub=_allow_stub)

agent = Graph(config=_config)

# Mirror AgentRegistry._compile_and_cache()'s conditional checkpointer — hitl.enabled
# or memory_enabled needs one, or interrupt()/memory silently no-ops on this path.
# NOT CheckpointerFactory (mediator/factory/checkpointer_factory.py): mediator* is
# excluded from the published wheel (pyproject.toml `include`), so templates cannot
# import it. This process runs exactly one agent, so the registry's cross-agent
# singleton-eviction concern (its own docstring) doesn't apply — a private MemorySaver
# per process is the standalone-path equivalent.
_hitl_enabled = agent.config.get("hitl", {}).get("enabled", False)
_needs_checkpointer = agent.config.get("memory_enabled") or _hitl_enabled
agent.compile(checkpointer=MemorySaver() if _needs_checkpointer else None)
agent.provision_secrets(_secrets_provider)


class InvokeRequest(BaseModel):
    input: str
    session_id: str = ""


def _bearer_matches(supplied: str, expected: str) -> bool:
    """Constant-time bearer comparison that is safe for non-ASCII header input."""
    return secrets.compare_digest(supplied.encode(), f"Bearer {expected}".encode())


def _resolve_standalone_trust(
    current: TrustLevel, authorization: str, invoke_auth_token: str | None, internal_runner_token: str | None
) -> TrustLevel:
    """Authenticate standalone callers without allowing external-token elevation.

    STG_INTERNAL_RUNNER_TOKEN is a distinct, CI-generated deployment credential.
    It is considered only for an anonymous caller and maps exactly to INTERNAL;
    INVOKE_AUTH_TOKEN remains VERIFIED_EXTERNAL. Middleware-established trust is
    never changed.
    """
    if current is not TrustLevel.ANONYMOUS:
        return current
    if internal_runner_token and _bearer_matches(authorization, internal_runner_token):
        return TrustLevel.INTERNAL
    if invoke_auth_token and _bearer_matches(authorization, invoke_auth_token):
        return TrustLevel.VERIFIED_EXTERNAL
    if internal_runner_token or invoke_auth_token:
        raise HTTPException(status_code=401, detail="Token is invalid or expired.")
    return TrustLevel.ANONYMOUS


@app.post("/invoke")
async def invoke(req: InvokeRequest, request: Request) -> Any:
    # This adapter is the entry-point auth boundary (standalone equivalent of
    # platform AuthMiddleware). Both values are deployment-level caller credentials,
    # not agent secrets: no InvocationContext exists before this boundary, so
    # ctx.secrets cannot apply.
    trust = _resolve_standalone_trust(
        getattr(request.state, "trust_level", TrustLevel.ANONYMOUS),
        request.headers.get("authorization", ""),
        os.environ.get("INVOKE_AUTH_TOKEN"),
        os.environ.get("STG_INTERNAL_RUNNER_TOKEN"),
    )
    with bound_secrets(agent._secrets_provider):
        ctx = InvocationContext(
            session_id=req.session_id or str(uuid4()),
            caller_trust_level=trust,
            caller_id=getattr(request.state, "caller_id", ""),
        )
        return agent.invoke(req.input, ctx=ctx)


@app.get("/health")
def health() -> Any:
    return {"status": "ok", "agent": "ret-c2-287"}
