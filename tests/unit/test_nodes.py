# RET-C2-287 — Unit tests: nodes

import json

from framework.schemas.agent_status import AgentStatus
from src.nodes.alert_dispatch_node import AlertDispatchNode
from src.nodes.alert_payload_build_node import AlertPayloadBuildNode
from src.nodes.anomaly_score_compute_node import AnomalyScoreComputeNode
from src.nodes.baseline_retrieve_node import BaselineRetrieveNode
from src.nodes.csi_ingest_node import CSIIngestNode
from src.nodes.flow_anomaly_classify_node import FlowAnomalyClassifyNode
from src.nodes.zone_occupancy_parse_node import ZoneOccupancyParseNode


def _st(**kw):
    base = {"node_history": [], "error_log": [], "correlation_id": "c1"}
    base.update(kw)
    return base


_FRAME = {"vendor": "cisco", "store_id": "S1", "timestamp": "2026-06-16T14:00:00", "weekday": 2,
          "zone_readings": [{"zone_id": "Z1", "rssi": 12, "frame_count": 120}]}


class TestCSIIngest:
    def test_success(self):
        r = CSIIngestNode().execute(_st(user_input=json.dumps(_FRAME)))
        assert r["status"] == AgentStatus.SUCCESS and r["zone_snapshot"]["zones"]

    def test_unknown_vendor_errors(self):
        bad = json.dumps({"vendor": "foo", "zone_readings": [{"zone_id": "Z1", "rssi": 1}]})
        assert CSIIngestNode().execute(_st(user_input=bad))["status"] == AgentStatus.ERROR

    def test_empty_errors(self):
        assert CSIIngestNode().execute(_st(user_input="  "))["status"] == AgentStatus.ERROR


class TestZoneOccupancyParse:
    def test_estimates(self):
        snap = {"store_id": "S1", "timestamp": "2026-06-16T14:00:00", "weekday": 2,
                "zones": [{"zone_id": "Z1", "rssi": 12, "frame_count": 120}]}
        r = ZoneOccupancyParseNode(occupancy_coeff={"rssi_to_count": 1.0}).execute(_st(user_input=json.dumps(snap)))
        assert r["occupancy_vector"][0]["occupancy"] == 12.0 and r["occupancy_vector"][0]["weekday"] == 2


class TestBaselineRetrieve:
    def test_lookup(self):
        vec = [{"zone_id": "Z1", "occupancy": 12.0, "hour_of_day": 14, "weekday": 2}]
        store = {"Z1|14|2": {"mean": 5.0, "std": 1.0, "sample_days": 28}}
        r = BaselineRetrieveNode(baseline_store=store).execute(_st(occupancy_vector=vec))
        assert r["baselines"]["Z1"]["mean"] == 5.0

    def test_upstream_error_passthrough(self):
        assert BaselineRetrieveNode().execute(_st(status=AgentStatus.ERROR.value))["status"] == AgentStatus.ERROR


class TestAnomalyScoreCompute:
    def test_zscore(self):
        vec = [{"zone_id": "Z1", "occupancy": 12.0, "flow_rate": 2.0}]
        baselines = {"Z1": {"mean": 5.0, "std": 1.0}}
        r = AnomalyScoreComputeNode().execute(_st(occupancy_vector=vec, baselines=baselines))
        assert r["anomaly_scores"][0]["z_score"] == 7.0


class TestFlowAnomalyClassify:
    def test_crowd_critical(self):
        scores = [{"zone_id": "Z1", "occupancy": 12, "z_score": 7.0, "flow_rate": 2.0}]
        r = FlowAnomalyClassifyNode(sigma=2.0).execute(_st(anomaly_scores=scores))
        c = r["anomaly_classifications"][0]
        assert c["anomaly_type"] == "CROWD" and c["severity"] == "critical"

    def test_normal(self):
        scores = [{"zone_id": "Z1", "occupancy": 5, "z_score": 0.5, "flow_rate": 1.0}]
        r = FlowAnomalyClassifyNode().execute(_st(anomaly_scores=scores))
        assert r["anomaly_classifications"][0]["anomaly_type"] == "NORMAL"


class TestAlertPayloadBuild:
    def test_builds_for_anomaly(self):
        cls = [{"zone_id": "Z1", "anomaly_type": "CROWD", "severity": "critical", "z_score": 7.0}]
        r = AlertPayloadBuildNode(min_severity="warning").execute(_st(zone_snapshot={"store_id": "S1"}, anomaly_classifications=cls))
        assert r["alert_payload"]["max_severity"] == "critical"
        assert "rssi" not in json.dumps(r["alert_payload"])  # APPI-safe

    def test_no_alert_when_normal(self):
        cls = [{"zone_id": "Z1", "anomaly_type": "NORMAL", "severity": "info"}]
        r = AlertPayloadBuildNode().execute(_st(zone_snapshot={"store_id": "S1"}, anomaly_classifications=cls))
        assert r["alert_payload"] == {}


class TestAlertDispatch:
    def test_s3_allowlist_gate(self):
        routing = {"allowlist": ["https://hooks.slack.com"],
                   "channels": [{"name": "slack", "webhook_url": "https://hooks.slack.com/x"},
                                {"name": "evil", "webhook_url": "https://evil.com/x"}]}
        payload = {"schema_version": "1.0", "store_id": "S1", "anomalies": [{"zone_id": "Z1"}], "max_severity": "critical"}
        r = AlertDispatchNode(alert_routing=routing).execute(_st(alert_payload=payload))
        statuses = {x["channel"]: x["status"] for x in r["delivery_receipts"]}
        assert statuses["slack"] in ("queued", "delivered")
        assert statuses["evil"] == "dropped"  # S-3 egress gate

    def test_no_alert_noop(self):
        r = AlertDispatchNode().execute(_st(alert_payload={}))
        assert r["status"] == AgentStatus.SUCCESS and r["delivery_receipts"] == []
