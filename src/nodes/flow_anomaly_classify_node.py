"""FlowAnomalyClassifyNode (inner step_d) — typed anomaly + severity classification.

Fourth node of the Cat 2 inner subgraph. Deterministic rule-based classification of each zone's Z-score
into CROWD / EMPTY / OCCUPANCY_DROP / QUEUE_OVERFLOW / NORMAL + severity via services/anomaly.classify. The σ
threshold is injected via config.

Node contract: execute(self, state) -> dict; partial update; status is an AgentStatus enum.
"""

from __future__ import annotations

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.trust_level import TrustLevel
from framework.schemas.agent_status import AgentStatus
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import RETC2287State
from src.services.anomaly import classify


class FlowAnomalyClassifyNode(FunctionNode):
    """Classify each zone's deviation into a typed anomaly + severity."""

    # S-1: inner-subgraph node — caller trust is verified at the outer
    # backbone; declaring least-privilege ANONYMOUS here (inner nodes never re-gate).
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def __init__(self, sigma: float = 2.0):
        self._sigma = sigma

    def execute(self, state: RETC2287State) -> dict[str, Any]:
        emit_trace_event("anomalies_classified", {"correlation_id": state.get("correlation_id")}, state)
        if state.get("status") in (AgentStatus.ERROR.value, AgentStatus.ERROR.value):
            return {"status": AgentStatus.ERROR.value}  # short-circuit: an upstream inner step already errored
        scores = state.get("anomaly_scores", [])
        if not scores:
            return {"status": AgentStatus.ERROR.value, "error_log": ["flow_classify: no anomaly scores"]}
        classifications = classify(scores, self._sigma)
        return {"anomaly_classifications": classifications, "status": AgentStatus.SUCCESS.value}
