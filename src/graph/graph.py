"""RETC2287Graph — Cat 2 outer graph (AgentBaseGraph, L1 direct).

Cat 2 pattern: the outer graph owns the fixed 5-node backbone (initialize → pre_process → main →
post_process → finalize); the multi-step occupancy-anomaly workflow is encapsulated in
OccupancyAnomalyGraphNode (a GraphNode) in the `main` slot, wrapping the inner
OccupancyAnomalyWorkflowGraph.

Node mapping (7 design steps → 5-node backbone):
  - CSIIngest               → pre_process (vendor parse, fail-fast unknown vendor)
  - ZoneOccupancyParse       ┐
  - BaselineRetrieve         │
  - AnomalyScoreCompute      ├→ inner OccupancyAnomalyWorkflowGraph (main via OccupancyAnomalyGraphNode)
  - FlowAnomalyClassify      │
  - AlertPayloadBuild        ┘ (APPI-safe, zone-level only)
  - AlertDispatch           → post_process (S-3 webhook allowlist gate + S-4 audit)

Public entry: Graph().compile() then .invoke(user_input, ctx=ctx). No _invoke_impl, no .run(),
no add_edges() override.
"""

from __future__ import annotations

from framework.graph.agent_base_graph import AgentBaseGraph

from src.nodes.alert_dispatch_node import AlertDispatchNode
from src.nodes.csi_ingest_node import CSIIngestNode
from src.nodes.occupancy_anomaly_graph_node import OccupancyAnomalyGraphNode
from src.schemas.state import RETC2287State


class RETC2287Graph(AgentBaseGraph):
    """Retail store WiFi-CSI occupancy & customer-flow anomaly alert (Cat 2, VectorRAG anomaly)."""

    @property
    def name(self) -> str:
        return "ret-c2-287"

    @property
    def state_schema(self) -> type:
        return RETC2287State

    def register_nodes(self) -> None:
        super().register_nodes()  # injects default initialize + finalize
        cfg = self.config if hasattr(self, "config") else {}
        self._nodes["pre_process"] = CSIIngestNode(vendor_strategies=cfg.get("vendor_strategies", {}))
        self._nodes["main"] = OccupancyAnomalyGraphNode(
            baseline_store=cfg.get("baseline_store", {}),
            occupancy_coeff=cfg.get("occupancy_coeff", {}),
            sigma=cfg.get("sigma", 2.0),
            min_severity=cfg.get("min_severity", "warning"),
        )
        self._nodes["post_process"] = AlertDispatchNode(
            alert_routing=cfg.get("alert_routing", {}),
            dispatcher=cfg.get("dispatcher"),
        )

    # add_edges() is NOT overridden — backbone wiring belongs to AgentBaseGraph.


# Alias so config/agent.yaml `module: "src.graph"` resolves a stable `Graph` symbol too.
Graph = RETC2287Graph
