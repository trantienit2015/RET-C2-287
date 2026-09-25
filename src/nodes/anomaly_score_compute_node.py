"""AnomalyScoreComputeNode (inner step_c) — Z-score per zone vs baseline.

Third node of the Cat 2 inner subgraph. Computes the Z-score per zone against its rolling baseline via
services/anomaly.compute_zscores. Deterministic.

Node contract: execute(self, state) -> dict; partial update; status is an AgentStatus enum.
"""

from __future__ import annotations

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.trust_level import TrustLevel
from framework.schemas.agent_status import AgentStatus
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import RETC2287State
from src.services.anomaly import compute_zscores


class AnomalyScoreComputeNode(FunctionNode):
    """Compute Z-scores vs baseline per zone."""

    # S-1: inner-subgraph node — caller trust is verified at the outer
    # backbone; declaring least-privilege ANONYMOUS here (inner nodes never re-gate).
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: RETC2287State) -> dict[str, Any]:
        emit_trace_event("anomaly_scores_computed", {"correlation_id": state.get("correlation_id")}, state)
        if state.get("status") in (AgentStatus.ERROR.value, AgentStatus.ERROR.value):
            return {"status": AgentStatus.ERROR.value}  # short-circuit: an upstream inner step already errored
        vector = state.get("occupancy_vector", [])
        baselines = state.get("baselines", {})
        if not vector:
            return {"status": AgentStatus.ERROR.value, "error_log": ["anomaly_score: no occupancy vector"]}
        scores = compute_zscores(vector, baselines)
        return {"anomaly_scores": scores, "status": AgentStatus.SUCCESS.value}
