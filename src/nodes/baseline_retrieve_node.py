"""BaselineRetrieveNode (inner step_b) — retrieve the 4-week rolling baseline per zone.

Second node of the Cat 2 inner subgraph. Looks up the rolling baseline (mean/std per zone × hour ×
weekday) from the injected baseline store via services/anomaly.retrieve_baselines. Side effect: baseline
retrieval — emit an S-4 audit.

Node contract: execute(self, state) -> dict; partial update; status is an AgentStatus enum.
"""

from __future__ import annotations

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.trust_level import TrustLevel
from framework.schemas.agent_status import AgentStatus
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import RETC2287State
from src.services.anomaly import retrieve_baselines


class BaselineRetrieveNode(FunctionNode):
    """Retrieve the rolling baseline for each zone."""

    # S-1: inner-subgraph node — caller trust is verified at the outer
    # backbone; declaring least-privilege ANONYMOUS here (inner nodes never re-gate).
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def __init__(self, baseline_store: Any = None) -> None:
        self._baseline_store = baseline_store or {}

    def execute(self, state: RETC2287State) -> dict[str, Any]:
        if state.get("status") in (AgentStatus.ERROR.value, AgentStatus.ERROR.value):
            return {"status": AgentStatus.ERROR.value}  # short-circuit: an upstream inner step already errored
        vector = state.get("occupancy_vector", [])
        if not vector:
            return {"status": AgentStatus.ERROR.value, "error_log": ["baseline_retrieve: no occupancy vector"]}
        baselines = retrieve_baselines(vector, self._baseline_store)
        emit_trace_event("baseline_retrieval", {"zones": len(vector)}, state)
        return {"baselines": baselines, "status": AgentStatus.SUCCESS.value}
