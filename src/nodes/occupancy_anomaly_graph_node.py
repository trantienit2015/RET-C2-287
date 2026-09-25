"""OccupancyAnomalyGraphNode — Cat 2 GraphNode assigned to the outer `main` slot.

Wraps the inner OccupancyAnomalyWorkflowGraph (ZoneOccupancyParse → BaselineRetrieve → AnomalyScoreCompute
→ FlowAnomalyClassify → AlertPayloadBuild). Per the Cat 2 contract: the outer graph owns the fixed 5-node
backbone; domain complexity is encapsulated here via get_subgraph(). The inner graph receives only a
string user_input + ctx, so extract_input() returns the JSON zone-snapshot payload.

GraphNode extends BaseNode directly (not FunctionNode) — it has no S-2/S-3 @final hooks; gating is
delegated to the inner subgraph's entry node (ZoneOccupancyParseNode, a FunctionNode). This wrapper's
own S-1 trust gate + the extract_input/merge_output boundary mapping are proven by
tests/proof_of_boundary/test_pb_graphnode_boundary.py (PB-6 excludes GraphNode from its src/nodes/
discovery, so this dedicated test covers what PB-6 cannot).
"""

from __future__ import annotations

from typing import Any, ClassVar, cast

from framework.nodes.graph_node import GraphNode
from framework.schemas.agent_state import AgentState
from framework.schemas.trust_level import TrustLevel


class OccupancyAnomalyGraphNode(GraphNode):
    """Inner-workflow wrapper for the occupancy-anomaly detection pipeline."""

    # S-1: outer main-slot wrapper — first node in the outer
    # backbone receiving caller input; matches agent.yaml required_trust_level.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.INTERNAL
    error_strategy: ClassVar[str] = "propagate"
    propagate_hitl: ClassVar[bool] = False

    def __init__(
        self, baseline_store: Any = None, occupancy_coeff: Any = None, sigma: float = 2.0, min_severity: str = "warning"
    ):
        super().__init__()
        self._baseline_store = baseline_store or {}
        self._occupancy_coeff = occupancy_coeff or {}
        self._sigma = sigma
        self._min_severity = min_severity

    def get_subgraph(self) -> Any:
        from src.graph.domain_workflow_graph import OccupancyAnomalyWorkflowGraph

        subgraph = OccupancyAnomalyWorkflowGraph(config=self._parent_config())
        subgraph.compile()
        return subgraph

    def extract_input(self, state: AgentState) -> str:
        return cast(str, state.get("validated_input", state.get("user_input", "")))

    def merge_output(self, state: AgentState, sub_result: dict[str, Any]) -> dict[str, Any]:
        return {
            "zone_snapshot": sub_result.get("zone_snapshot", {}),
            "occupancy_vector": sub_result.get("occupancy_vector", []),
            "baselines": sub_result.get("baselines", {}),
            "anomaly_scores": sub_result.get("anomaly_scores", []),
            "anomaly_classifications": sub_result.get("anomaly_classifications", []),
            "alert_payload": sub_result.get("alert_payload", {}),
            "status": sub_result.get("status"),
        }

    def _parent_config(self) -> dict[str, Any]:
        return {
            "baseline_store": self._baseline_store,
            "occupancy_coeff": self._occupancy_coeff,
            "sigma": self._sigma,
            "min_severity": self._min_severity,
        }
