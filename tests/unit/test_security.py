"""Security tests — S-1 trust gate (framework-enforced via __call__).

CSIIngestNode declares required_trust_level = INTERNAL. The trust gate lives in BaseNode.__call__ and
reads state["caller_trust_level"], exercised by calling the node (node(state)), NOT execute().
"""
import json

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from src.nodes.csi_ingest_node import CSIIngestNode

_PAYLOAD = json.dumps({"vendor": "cisco", "store_id": "S1", "zone_readings": [{"zone_id": "Z1", "rssi": 5}]})


def _state(trust):
    return {"user_input": _PAYLOAD, "caller_trust_level": trust, "node_history": [],
            "error_log": [], "execution_time": {}, "status": None}


class TestS1TrustGate:
    def test_node_declares_internal(self):
        assert CSIIngestNode.required_trust_level == TrustLevel.INTERNAL

    def test_anonymous_blocked(self):
        result = CSIIngestNode()(_state(TrustLevel.ANONYMOUS.value))  # via __call__
        assert result.get("status") == AgentStatus.ERROR.value
        assert any("S-1 trust gate denied" in e for e in result.get("error_log", []))

    def test_internal_allowed(self):
        result = CSIIngestNode()(_state(TrustLevel.INTERNAL.value))
        assert "S-1 trust gate denied" not in str(result.get("error_log", []))
