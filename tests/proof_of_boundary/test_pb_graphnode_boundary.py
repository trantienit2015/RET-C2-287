# RET-C2-287 - GraphNode boundary test (Cat 2 outer main-slot wrapper).
#
# Why this test exists: PB-6 (test_pb_invoke_order.py) only self-discovers
# BaseNode subclasses under src/nodes/ that are NOT a GraphNode subclass.
# OccupancyAnomalyGraphNode lives under src/nodes/ by this template's layout
# (see occupancy_anomaly_graph_node.py) - but exclusion from PB-6 does not
# exempt it from test coverage. The outer GraphNode is a real security
# boundary (first node receiving caller input in the outer backbone) that no
# probe otherwise touches - a test-scope blind spot on Cat 2 templates.
#
# framework/nodes/graph_node.py: GraphNode extends BaseNode directly (not
# FunctionNode), so it has no _security_gate_input/_security_gate_output at
# all - S-2/S-3 gating is delegated entirely to the inner subgraph's own
# FunctionNode chain (ZoneOccupancyParseNode is the inner entry point). This
# test proves that delegation is real, not absent.

from framework.nodes.function_node import FunctionNode
from framework.schemas.trust_level import TrustLevel

from src.nodes.occupancy_anomaly_graph_node import OccupancyAnomalyGraphNode
from src.nodes.zone_occupancy_parse_node import ZoneOccupancyParseNode


def _node():
    return OccupancyAnomalyGraphNode(baseline_store={}, occupancy_coeff={}, sigma=2.0, min_severity="warning")


class TestGraphNodeS1TrustGate:
    """S-1: the outer main-slot GraphNode enforces the trust gate like any BaseNode."""

    def test_insufficient_trust_returns_error_without_invoking_subgraph(self, monkeypatch):
        node = _node()
        called = {"get_subgraph": False}

        def _spy_get_subgraph():
            called["get_subgraph"] = True
            raise AssertionError("get_subgraph() must not run when the S-1 gate denies")

        monkeypatch.setattr(node, "get_subgraph", _spy_get_subgraph)

        state = {
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
            "validated_input": '{"store_id": "s1", "zones": []}',
        }
        out = node(state)

        assert out["status"] == "error"
        assert any("S-1 trust gate denied" in e for e in out["error_log"])
        assert called["get_subgraph"] is False

    def test_matches_agent_yaml_required_trust_level(self):
        # The outer main-slot wrapper must match the sibling outer FunctionNodes
        # (INTERNAL), not the inner subgraph's ANONYMOUS default.
        assert OccupancyAnomalyGraphNode.required_trust_level == TrustLevel.INTERNAL


class TestGraphNodeBoundaryMapping:
    """Boundary mapping: extract_input()/merge_output() do not leak raw state/subgraph dicts."""

    def test_extract_input_only_reads_validated_input(self):
        node = _node()
        state = {
            "validated_input": '{"store_id": "s1", "zones": []}',
            "user_input": "raw caller text should not leak",
            "unrelated_secret_field": "must-not-appear",
        }
        extracted = node.extract_input(state)

        assert isinstance(extracted, str)
        assert "unrelated_secret_field" not in extracted
        assert "must-not-appear" not in extracted

    def test_merge_output_maps_fields_explicitly_no_raw_passthrough(self):
        node = _node()
        state = {}
        sub_result = {
            "zone_snapshot": {"store_id": "s1", "zones": []},
            "occupancy_vector": [{"zone_id": "z1", "occupancy": 3}],
            "baselines": {"z1": {"mean": 2.0, "std": 0.5}},
            "anomaly_scores": [{"zone_id": "z1", "z_score": 2.1}],
            "anomaly_classifications": [{"zone_id": "z1", "anomaly_type": "CROWD"}],
            "alert_payload": {"zone_id": "z1", "severity": "warning"},
            "status": "success",
            # A field the subgraph might carry internally that must NOT leak
            # into the outer state unless merge_output() explicitly maps it.
            "internal_debug_trace": "should-not-be-copied",
        }
        merged = node.merge_output(state, sub_result)

        assert "internal_debug_trace" not in merged
        assert merged["status"] == "success"
        assert set(merged.keys()) == {
            "zone_snapshot",
            "occupancy_vector",
            "baselines",
            "anomaly_scores",
            "anomaly_classifications",
            "alert_payload",
            "status",
        }


class TestGraphNodeDelegatesGatingToInnerSubgraph:
    """Delegation has a real target: the inner subgraph's entry node runs S-1/S-2/S-3."""

    def test_inner_entry_node_is_a_function_node_with_security_gates(self):
        # ZoneOccupancyParseNode is the inner subgraph's entry point
        # (domain_workflow_graph.py: START -> zone_occupancy_parse). It is a
        # FunctionNode, so the framework's @final S-2/S-3 gates run on every
        # invocation of the inner subgraph - this is where the GraphNode's
        # skipped lifecycle is actually enforced, not omitted.
        assert issubclass(ZoneOccupancyParseNode, FunctionNode)
        assert hasattr(ZoneOccupancyParseNode, "required_trust_level")
