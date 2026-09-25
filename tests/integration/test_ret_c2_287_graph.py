# RET-C2-287 — Integration tests: full outer graph compile() + invoke()

import json

from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from src.graph.graph import Graph

_BASELINE = {"Z1|14|2": {"mean": 5.0, "std": 1.0, "sample_days": 28}, "Z2|14|2": {"mean": 3.0, "std": 1.0, "sample_days": 28}}
_ROUTING = {"allowlist": ["https://hooks.slack.com"],
            "channels": [{"name": "slack", "webhook_url": "https://hooks.slack.com/x"},
                         {"name": "evil", "webhook_url": "https://evil.com/x"}]}


def _agent(dispatcher=None):
    agent = Graph(config={"baseline_store": _BASELINE, "sigma": 2.0, "min_severity": "warning",
                          "alert_routing": _ROUTING, "occupancy_coeff": {"rssi_to_count": 1.0},
                          "dispatcher": dispatcher})
    agent.compile()
    return agent


class _RecordingDispatcher:
    """Adapter-shaped dispatcher: same `send(url, payload)` interface build_dispatcher() returns."""

    def __init__(self):
        self.sent = []

    def send(self, url: str, payload: dict) -> dict:
        self.sent.append((url, payload))
        return {"status": "sent", "http_status": 200}


def _ctx():
    return InvocationContext(session_id="s1", caller_trust_level=TrustLevel.INTERNAL, caller_id="store1")


_FRAME = {"vendor": "cisco", "store_id": "S001", "timestamp": "2026-06-16T14:30:00", "weekday": 2,
          "zone_readings": [{"zone_id": "Z1", "rssi": 12, "frame_count": 120}, {"zone_id": "Z2", "rssi": 3, "frame_count": 60}]}


class TestRETC2287Graph:
    def test_crowd_alert_with_s3_gate(self):
        r = _agent().invoke(json.dumps(_FRAME), ctx=_ctx())
        assert r["status"] in (AgentStatus.SUCCESS, AgentStatus.SUCCESS.value)
        out = r.get("output") or r.get("formatted_output")
        assert out["alert"]["max_severity"] == "critical"
        # APPI-safe: no device/rssi data in the dispatched alert
        assert "rssi" not in json.dumps(out["alert"])
        # S-3 egress gate: evil.com dropped, slack allowed
        st = {x["channel"]: x["status"] for x in out["delivery_receipts"]}
        # No dispatcher configured in this case → 'queued' is the exact expected state.
        assert st["evil"] == "dropped" and st["slack"] == "queued"

    def test_configured_dispatcher_actually_delivers(self):
        """End-to-end: a wired dispatcher must really send, not report 'queued'/'failed'.

        This is the regression that the previous permissive oracle allowed through: the adapter
        returned a bare callable while `dispatch()` calls `.send(url, payload)`, so every live
        dispatch raised AttributeError and was recorded as 'failed'.
        """
        disp = _RecordingDispatcher()
        r = _agent(dispatcher=disp).invoke(json.dumps(_FRAME), ctx=_ctx())
        assert r["status"] in (AgentStatus.SUCCESS, AgentStatus.SUCCESS.value)
        out = r.get("output") or r.get("formatted_output")
        st = {x["channel"]: x["status"] for x in out["delivery_receipts"]}
        assert st["slack"] == "delivered", out["delivery_receipts"]
        assert st["evil"] == "dropped"
        # Only the allowlisted channel was actually transmitted to.
        assert [u for u, _ in disp.sent] == ["https://hooks.slack.com/x"]
        assert disp.sent[0][1]["max_severity"] == "critical"

    def test_adapter_built_dispatcher_satisfies_the_dispatch_interface(self):
        """The production adapter's return value must be usable by services.alert.dispatch."""
        from src.services.deploy_adapter import build_dispatcher

        class _S:
            def require(self, k):
                return "tok"

        built = build_dispatcher(_S(), allow_stub=False)
        assert callable(getattr(built, "send", None)), type(built).__name__

    def test_all_normal_no_alert(self):
        frame = {"vendor": "cisco", "store_id": "S001", "timestamp": "2026-06-16T14:30:00", "weekday": 2,
                 "zone_readings": [{"zone_id": "Z1", "rssi": 5, "frame_count": 60}]}
        r = _agent().invoke(json.dumps(frame), ctx=_ctx())
        out = r.get("output") or r.get("formatted_output")
        assert out["alert"] is None

    def test_backbone_node_history(self):
        r = _agent().invoke(json.dumps(_FRAME), ctx=_ctx())
        h = r.get("node_history", [])
        assert "CSIIngestNode" in h and "OccupancyAnomalyGraphNode" in h and "AlertDispatchNode" in h

    def test_unknown_vendor_errors(self):
        bad = json.dumps({"vendor": "foo", "zone_readings": [{"zone_id": "Z1", "rssi": 1}]})
        assert _agent().invoke(bad, ctx=_ctx())["status"] in (AgentStatus.ERROR, AgentStatus.ERROR.value)

    def test_empty_errors(self):
        assert _agent().invoke("", ctx=_ctx())["status"] in (AgentStatus.ERROR, AgentStatus.ERROR.value)
