# RET-C2-287 - contract tests for the deploy-time resource adapter +
# Trust-level declarations across all FunctionNodes.

import pytest

from framework.schemas.trust_level import TrustLevel

from src.services.deploy_adapter import (
    DeployConfigError,
    build_baseline_store,
    build_dispatcher,
)

_STUB_FLAG = "RET_C2_287_ALLOW_STUB_DEPLOY"
_STG_MOCK_FLAG = "STG_MOCK_MODE"


class _Secrets:
    def __init__(self, values):
        self._values = values

    def require(self, key):
        if key not in self._values:
            raise KeyError(key)
        return self._values[key]


# ---- baseline store --------------------------------------------------

def test_baseline_missing_key_raises():
    with pytest.raises(DeployConfigError):
        build_baseline_store(_Secrets({"BASELINE_STORE_URL": "https://b.example"}), allow_stub=False)


def test_baseline_no_provider_raises():
    with pytest.raises(DeployConfigError):
        build_baseline_store(None, allow_stub=False)


def test_baseline_stub_requires_flag(monkeypatch):
    monkeypatch.delenv(_STUB_FLAG, raising=False)
    monkeypatch.delenv(_STG_MOCK_FLAG, raising=False)
    with pytest.raises(DeployConfigError):
        build_baseline_store(None, allow_stub=True)


def test_baseline_stub_opt_in(monkeypatch):
    monkeypatch.setenv(_STUB_FLAG, "1")
    assert build_baseline_store(None, allow_stub=True) == {}


# ---- dispatcher ------------------------------------------------------

def test_dispatcher_missing_token_raises():
    with pytest.raises(DeployConfigError):
        build_dispatcher(_Secrets({}), allow_stub=False)


def test_dispatcher_stub_opt_in(monkeypatch):
    monkeypatch.setenv(_STUB_FLAG, "1")
    assert build_dispatcher(None, allow_stub=True) is None


def test_stg_mock_mode_selects_stub(monkeypatch):
    # The CI deploy-stg job sets STG_MOCK_MODE=true (no real secrets, no egress).
    monkeypatch.delenv(_STUB_FLAG, raising=False)
    monkeypatch.setenv(_STG_MOCK_FLAG, "true")
    assert build_baseline_store(None, allow_stub=True) == {}
    assert build_dispatcher(None, allow_stub=True) is None


def test_stg_mock_mode_alone_never_bypasses_production(monkeypatch):
    # The env signal alone does not select the stand-in: the caller must opt in too.
    monkeypatch.delenv(_STUB_FLAG, raising=False)
    monkeypatch.setenv(_STG_MOCK_FLAG, "true")
    with pytest.raises(DeployConfigError):
        build_dispatcher(_Secrets({}), allow_stub=False)


# ---- trust declarations ---------------------------------------------

def test_all_functionnodes_declare_trust():
    from src.nodes.alert_dispatch_node import AlertDispatchNode
    from src.nodes.alert_payload_build_node import AlertPayloadBuildNode
    from src.nodes.anomaly_score_compute_node import AnomalyScoreComputeNode
    from src.nodes.baseline_retrieve_node import BaselineRetrieveNode
    from src.nodes.csi_ingest_node import CSIIngestNode
    from src.nodes.flow_anomaly_classify_node import FlowAnomalyClassifyNode
    from src.nodes.occupancy_anomaly_graph_node import OccupancyAnomalyGraphNode
    from src.nodes.zone_occupancy_parse_node import ZoneOccupancyParseNode

    inner = [ZoneOccupancyParseNode, BaselineRetrieveNode, AnomalyScoreComputeNode,
             FlowAnomalyClassifyNode, AlertPayloadBuildNode]
    outer = [CSIIngestNode, AlertDispatchNode, OccupancyAnomalyGraphNode]

    for cls in inner:
        assert cls.required_trust_level == TrustLevel.ANONYMOUS, cls.__name__
    for cls in outer:
        assert cls.required_trust_level == TrustLevel.INTERNAL, cls.__name__
