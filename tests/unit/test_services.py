# RET-C2-287 — Unit tests: deterministic services (csi / anomaly / alert)

import pytest

from src.services.alert import build_alert, dispatch, url_allowed
from src.services.anomaly import classify, compute_zscores, retrieve_baselines
from src.services.csi import estimate_occupancy, parse_frame


class TestCSI:
    def test_parse_carries_weekday(self):
        snap = parse_frame({"vendor": "cisco", "weekday": 2, "zone_readings": [{"zone_id": "Z1", "rssi": 5}]})
        assert snap["weekday"] == 2 and snap["vendor"] == "cisco"

    def test_unknown_vendor_raises(self):
        with pytest.raises(ValueError):
            parse_frame({"vendor": "foo", "zone_readings": []})

    def test_estimate_occupancy(self):
        snap = {"timestamp": "2026-06-16T14:00:00", "weekday": 2, "zones": [{"zone_id": "Z1", "rssi": 12, "frame_count": 120}]}
        vec = estimate_occupancy(snap, {"rssi_to_count": 1.0})
        assert vec[0]["occupancy"] == 12.0 and vec[0]["hour_of_day"] == 14


class TestAnomaly:
    def test_baseline_bucket(self):
        vec = [{"zone_id": "Z1", "occupancy": 12, "hour_of_day": 14, "weekday": 2}]
        b = retrieve_baselines(vec, {"Z1|14|2": {"mean": 5.0, "std": 1.0, "sample_days": 28}})
        assert b["Z1"]["mean"] == 5.0

    def test_zscore(self):
        s = compute_zscores([{"zone_id": "Z1", "occupancy": 12.0, "flow_rate": 2.0}], {"Z1": {"mean": 5.0, "std": 1.0}})
        assert s[0]["z_score"] == 7.0

    def test_zscore_no_baseline(self):
        s = compute_zscores([{"zone_id": "Z1", "occupancy": 12.0}], {"Z1": {"mean": 0, "std": 0}})
        assert s[0]["z_score"] == 0.0

    def test_classify_crowd_and_empty(self):
        assert classify([{"zone_id": "Z1", "z_score": 7.0, "flow_rate": 2.0}])[0]["anomaly_type"] == "CROWD"
        assert classify([{"zone_id": "Z2", "z_score": -4.0, "flow_rate": 0.0}])[0]["anomaly_type"] == "EMPTY"
        assert classify([{"zone_id": "Z3", "z_score": 0.3}])[0]["anomaly_type"] == "NORMAL"

    def test_classify_negative_occupancy_labels_occupancy_drop(self):
        # a mild negative OCCUPANCY z-score must be labelled OCCUPANCY_DROP,
        # not the unsupported FLOW_DROP (no independent flow baseline exists).
        out = classify([{"zone_id": "Z1", "z_score": -2.5, "flow_rate": 1.0}], sigma=2.0)
        assert out[0]["anomaly_type"] == "OCCUPANCY_DROP"
        # the retired label must not reappear
        assert out[0]["anomaly_type"] != "FLOW_DROP"

    def test_severe_positive_zscore_is_crowd_regardless_of_flow_rate(self):
        # Same root cause: flow_rate is a single-frame count with no baseline,
        # so it must not select a distinct QUEUE_OVERFLOW class.
        low_flow = classify([{"zone_id": "Z1", "z_score": 7.0, "flow_rate": 0.0}], sigma=2.0)
        high_flow = classify([{"zone_id": "Z1", "z_score": 7.0, "flow_rate": 9.0}], sigma=2.0)
        assert low_flow[0]["anomaly_type"] == "CROWD"
        assert high_flow[0]["anomaly_type"] == "CROWD"
        assert "QUEUE_OVERFLOW" not in {low_flow[0]["anomaly_type"], high_flow[0]["anomaly_type"]}


class TestAlert:
    def test_build_alert_filters_severity(self):
        cls = [{"zone_id": "Z1", "anomaly_type": "CROWD", "severity": "critical"},
               {"zone_id": "Z2", "anomaly_type": "NORMAL", "severity": "info"}]
        a = build_alert("S1", cls, "warning")
        assert len(a["anomalies"]) == 1 and a["max_severity"] == "critical"

    def test_build_alert_empty_when_normal(self):
        assert build_alert("S1", [{"zone_id": "Z1", "anomaly_type": "NORMAL", "severity": "info"}], "warning") == {}

    def test_url_allowed(self):
        assert url_allowed("https://hooks.slack.com/x", ["https://hooks.slack.com"])
        assert not url_allowed("https://evil.com/x", ["https://hooks.slack.com"])
        assert not url_allowed("https://x.com", [])  # fail-closed

    def test_dispatch_gates(self):
        routing = {"allowlist": ["https://ok.com"],
                   "channels": [{"name": "ok", "webhook_url": "https://ok.com/x"},
                                {"name": "bad", "webhook_url": "https://bad.com/x"}]}
        receipts = dispatch({"x": 1}, routing)
        st = {r["channel"]: r["status"] for r in receipts}
        assert st["ok"] == "queued" and st["bad"] == "dropped"

    def test_dispatch_delivers_through_a_conforming_dispatcher(self):
        sent = []

        class _D:
            def send(self, url, payload):
                sent.append((url, payload))
                return {"status": "sent"}

        routing = {"allowlist": ["https://ok.com"], "channels": [{"name": "ok", "webhook_url": "https://ok.com/x"}]}
        receipts = dispatch({"x": 1}, routing, _D())
        assert receipts[0]["status"] == "delivered"
        assert sent == [("https://ok.com/x", {"x": 1})]

    def test_dispatch_rejects_a_dispatcher_without_send(self):
        """A wiring defect must surface as TypeError, not a per-channel 'failed' receipt.

        Regression: the deploy adapter used to return a bare callable while dispatch() calls
        `.send(...)`, so every live dispatch raised AttributeError and was silently absorbed.
        """
        routing = {"allowlist": ["https://ok.com"], "channels": [{"name": "ok", "webhook_url": "https://ok.com/x"}]}
        with pytest.raises(TypeError, match="send"):
            dispatch({"x": 1}, routing, lambda name, url, payload: None)

    def test_dispatch_records_transport_failure_per_channel(self):
        class _Boom:
            def send(self, url, payload):
                raise RuntimeError("upstream 503")

        routing = {"allowlist": ["https://ok.com"], "channels": [{"name": "ok", "webhook_url": "https://ok.com/x"}]}
        receipts = dispatch({"x": 1}, routing, _Boom())
        assert receipts[0]["status"] == "failed" and "503" in receipts[0]["reason"]
