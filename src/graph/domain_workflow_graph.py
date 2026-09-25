"""OccupancyAnomalyWorkflowGraph — Cat 2 inner domain workflow graph.

Inherits BaseGraph directly for a fully custom linear topology:

    START → zone_occupancy_parse → baseline_retrieve → anomaly_score_compute
          → flow_anomaly_classify → alert_payload_build → END

Instantiated by OccupancyAnomalyGraphNode.get_subgraph() in the outer graph's `main` slot. The five steps
are the occupancy-anomaly workflow; deterministic compute lives in services/. get_output() shapes the
sub_result consumed by the outer merge_output(). Downstream nodes short-circuit on an upstream error.

Implements all 7 BaseGraph abstract methods. register_nodes() does NOT call super() (abstract in
BaseGraph) and does NOT register initialize/finalize (outer backbone concern).
"""

from __future__ import annotations

from typing import Any
from langgraph.graph import END, START

from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus

from src.nodes.alert_payload_build_node import AlertPayloadBuildNode
from src.nodes.anomaly_score_compute_node import AnomalyScoreComputeNode
from src.nodes.baseline_retrieve_node import BaselineRetrieveNode
from src.nodes.flow_anomaly_classify_node import FlowAnomalyClassifyNode
from src.nodes.zone_occupancy_parse_node import ZoneOccupancyParseNode
from src.schemas.state import RETC2287State


class OccupancyAnomalyWorkflowGraph(BaseGraph):
    """Inner workflow: occupancy → baseline → z-score → classify → alert-payload."""

    @property
    def name(self) -> str:
        return "occupancy_anomaly_workflow"

    @property
    def state_schema(self) -> type:
        return RETC2287State

    def _validate_config(self) -> None:
        pass

    def register_nodes(self) -> None:
        cfg = self.config if hasattr(self, "config") else {}
        self._nodes["zone_occupancy_parse"] = ZoneOccupancyParseNode(occupancy_coeff=cfg.get("occupancy_coeff", {}))
        self._nodes["baseline_retrieve"] = BaselineRetrieveNode(baseline_store=cfg.get("baseline_store", {}))
        self._nodes["anomaly_score_compute"] = AnomalyScoreComputeNode()
        self._nodes["flow_anomaly_classify"] = FlowAnomalyClassifyNode(sigma=cfg.get("sigma", 2.0))
        self._nodes["alert_payload_build"] = AlertPayloadBuildNode(min_severity=cfg.get("min_severity", "warning"))

    def add_edges(self) -> None:
        self._sg.add_edge(START, "zone_occupancy_parse")
        self._sg.add_edge("zone_occupancy_parse", "baseline_retrieve")
        self._sg.add_edge("baseline_retrieve", "anomaly_score_compute")
        self._sg.add_edge("anomaly_score_compute", "flow_anomaly_classify")
        self._sg.add_edge("flow_anomaly_classify", "alert_payload_build")
        self._sg.add_edge("alert_payload_build", END)

    def route(self, state: AgentState) -> str:
        return END if state.get("status") == AgentStatus.ERROR.value else "alert_payload_build"

    def get_output(self, state: AgentState) -> dict[str, Any]:
        return {
            "zone_snapshot": state.get("zone_snapshot", {}),
            "occupancy_vector": state.get("occupancy_vector", []),
            "baselines": state.get("baselines", {}),
            "anomaly_scores": state.get("anomaly_scores", []),
            "anomaly_classifications": state.get("anomaly_classifications", []),
            "alert_payload": state.get("alert_payload", {}),
            "status": state.get("status"),
            "trace_id": state.get("trace_id"),
            "correlation_id": state.get("correlation_id"),
            "node_history": state.get("node_history", []),
        }
