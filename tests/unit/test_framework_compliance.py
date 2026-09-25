# RET-C2-287 - Framework compliance tests TC-01..TC-08 (proactive code-review audit).
# Shared compliance-test shape,
# adapted to this template's real architecture (Cat 2: outer pre/main(GraphNode)/post + inner subgraph).

import os
import re

import pytest
from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.nodes.alert_dispatch_node import AlertDispatchNode
from src.nodes.alert_payload_build_node import AlertPayloadBuildNode
from src.nodes.anomaly_score_compute_node import AnomalyScoreComputeNode
from src.nodes.baseline_retrieve_node import BaselineRetrieveNode
from src.nodes.csi_ingest_node import CSIIngestNode
from src.nodes.flow_anomaly_classify_node import FlowAnomalyClassifyNode
from src.nodes.zone_occupancy_parse_node import ZoneOccupancyParseNode
from src.schemas.state import RETC2287State

_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "src")
TRUST = TrustLevel.INTERNAL.value

_VALID_CSI_FRAME = (
    '{"vendor": "cisco", "store_id": "s1", "timestamp": "2026-01-01T10:00:00", "weekday": 1, '
    '"zone_readings": [{"zone_id": "z1", "rssi": -40, "frame_count": 120}]}'
)


def _src_files():
    for root, _d, files in os.walk(_SRC):
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(root, f)


# TC-01 - State is a flat TypedDict extending AgentState, added fields are primitives/JSON-safe.
class TestTC01StateContract:
    def test_state_is_typeddict_extending_agent_state(self):
        assert hasattr(RETC2287State, "__annotations__")
        assert "user_input" in RETC2287State.__annotations__
        assert set(AgentState.__annotations__).issubset(set(RETC2287State.__annotations__))

    def test_added_fields_are_primitives_or_json_safe(self):
        import typing

        added = [k for k in RETC2287State.__annotations__ if k not in AgentState.__annotations__]
        assert added, "State must declare agent-specific fields"
        # RET-C2-287 stores compound telemetry as native dict/list[dict] (JSON-serializable,
        # not JSON-string-encoded — ADR-005's to_json/from_json wrapper is optional per
        # the State contract). Leaf primitives allowed inside those containers too.
        allowed = {"str", "int", "bool", "float", "dict", "list", "NoneType"}
        # `from __future__ import annotations` means raw __annotations__ are unevaluated
        # strings/ForwardRefs; resolve via get_type_hints (and unwrap NotRequired[...]).
        hints = typing.get_type_hints(RETC2287State, include_extras=True)
        for name in added:
            ann = hints[name]
            leaf_names = set()

            def _collect(t):
                origin = typing.get_origin(t)
                if origin is None:
                    leaf_names.add(getattr(t, "__name__", str(t)))
                    return
                for arg in typing.get_args(t):
                    _collect(arg)

            _collect(ann)
            assert leaf_names <= allowed, f"{name}: {leaf_names} not JSON-safe"

    def test_all_agent_specific_fields_are_not_required(self):
        # criterion C8: every agent-specific field must be NotRequired (checkpoint/mid-pipeline
        # KeyError safety).
        added = [k for k in RETC2287State.__annotations__ if k not in AgentState.__annotations__]
        hints_raw = RETC2287State.__annotations__
        for name in added:
            assert "NotRequired" in str(hints_raw[name]), f"{name} must be wrapped in NotRequired[...]"


# TC-02 - Empty/missing input yields a fail-closed ERROR outcome, no raise.
class TestTC02Validation:
    def test_empty_input_no_raise(self):
        node = CSIIngestNode()
        out = node.execute({"user_input": ""})
        assert out["status"] == AgentStatus.ERROR.value
        assert out["error_log"]

    def test_missing_zones_no_raise(self):
        node = ZoneOccupancyParseNode()
        out = node.execute({"user_input": '{"store_id": "s1"}'})
        assert out["status"] == AgentStatus.ERROR.value
        assert out["error_log"]


# TC-03 - No JWT / API keys / secrets in src/; no direct os.environ reads for secrets.
class TestTC03NoCredentials:
    def test_no_credential_literals(self):
        pat = re.compile(r"(sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)")
        offenders = []
        for fp in _src_files():
            with open(fp, encoding="utf-8") as f:
                if pat.search(f.read()):
                    offenders.append(fp)
        assert offenders == []

    def test_no_secret_read_via_os_environ(self):
        # src/api/server.py reads RET_C2_287_ALLOW_STUB_DEPLOY / STG_MOCK_MODE (non-production
        # opt-in flags) via os.environ by design; they are not secrets. The actual secrets
        # (BASELINE_STORE_API_KEY, BASELINE_STORE_URL, ALERT_DISPATCH_TOKEN — declared in
        # agent.yaml requires.secrets) must never be read via os.environ - only via
        # ctx.secrets.require().
        offenders = []
        # INVOKE_AUTH_TOKEN is the entry-point caller-auth credential: read in
        # src/api/server.py BEFORE any InvocationContext exists, so ctx.secrets cannot
        # apply. It authenticates the caller of the deployment - not an agent secret,
        # and it never enters state. STG_INTERNAL_RUNNER_TOKEN is the separate STG-only
        # runner credential read at the same boundary for the same reason.
        allowed_non_secret = {"INVOKE_AUTH_TOKEN", "STG_INTERNAL_RUNNER_TOKEN"}
        pat = re.compile(r'os\.environ(?:\.get)?\(\s*["\']([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z0-9_]*)["\']')
        for fp in _src_files():
            with open(fp, encoding="utf-8") as f:
                content = f.read()
                names = set(pat.findall(content))
                if names - allowed_non_secret:
                    offenders.append(fp)
        assert offenders == []


# TC-04 - InvocationContext is never stored in State after invoke.
class TestTC04ContextIsolation:
    def test_no_invocationcontext_in_state_after_invoke(self):
        from src.graph.graph import Graph

        agent = Graph()
        agent.compile()
        ctx = InvocationContext(session_id="tc04", caller_trust_level=TrustLevel.INTERNAL, caller_id="tc04")
        result = agent.invoke(_VALID_CSI_FRAME, ctx=ctx)
        for v in result.values():
            assert not isinstance(v, InvocationContext)

    def test_from_state_available(self):
        assert hasattr(InvocationContext, "from_state")


# TC-05 - Domain events: nodes emit >=1 domain event; no node under src/nodes/
# ever re-emits a framework backbone lifecycle event (node_start/complete/error/skip).
class TestTC05Audit:
    def test_node_emits_domain_event(self, monkeypatch):
        import src.nodes.zone_occupancy_parse_node as mod

        events = []
        monkeypatch.setattr(mod, "emit_trace_event", lambda e, p, s: events.append(e))
        # valid but minimal snapshot with one zone to reach SUCCESS
        state = {"user_input": '{"store_id": "s1", "vendor": "cisco", "zones": [{"zone_id": "z1", "rssi": -40, "frame_count": 120}]}'}
        out = ZoneOccupancyParseNode().execute(state)
        assert out["status"] == AgentStatus.SUCCESS.value
        assert len(events) >= 1
        assert "zone_occupancy_parsed" in events
        assert not ({"node_start", "node_complete", "node_error", "node_skip"} & set(events))

    def test_source_has_no_backbone_events(self):
        pat = re.compile(r'emit_trace_event\(\s*["\'](node_start|node_complete|node_error|node_skip)["\']')
        offenders = []
        for fp in _src_files():
            with open(fp, encoding="utf-8") as f:
                if pat.search(f.read()):
                    offenders.append(fp)
        assert offenders == []


# TC-06 / TC-07 - S-2/S-3 gates are @final on FunctionNode (overriding raises TypeError at class def).
class TestTC0607FinalGates:
    def test_input_gate_is_final(self):
        with pytest.raises(TypeError):

            class BadIn(FunctionNode):  # noqa: N801
                def _security_gate_input(self, state):
                    return state

    def test_output_gate_is_final(self):
        with pytest.raises(TypeError):

            class BadOut(FunctionNode):  # noqa: N801
                def _security_gate_output(self, result):
                    return result

    def test_output_gate_blocks_credentials(self):
        # The @final S-3 credential scan actually fires (not vacuous): a credential in
        # the result is blocked, never returned as-is. No node in this template overrides
        # _extra_security_gate_output — the base @final scan alone must still catch this.
        node = AlertDispatchNode()
        with pytest.raises(Exception):
            node._security_gate_output({"formatted_output": "token AKIAIOSFODNN7EXAMPLE leaked"})


# TC-08 - required_trust_level enforced: insufficient trust -> ERROR state, no raise.
class TestTC08TrustGate:
    def test_declared_trust_levels_valid(self):
        for cls in (
            CSIIngestNode,
            ZoneOccupancyParseNode,
            BaselineRetrieveNode,
            AnomalyScoreComputeNode,
            FlowAnomalyClassifyNode,
            AlertPayloadBuildNode,
            AlertDispatchNode,
        ):
            assert cls.required_trust_level in (TrustLevel.ANONYMOUS, TrustLevel.VERIFIED_EXTERNAL, TrustLevel.INTERNAL)

    def test_insufficient_trust_returns_error(self):
        node = CSIIngestNode()
        out = node({"caller_trust_level": TrustLevel.ANONYMOUS.value, "user_input": _VALID_CSI_FRAME})
        assert str(out.get("status")).lower().endswith("error")

    def test_sufficient_trust_succeeds(self):
        node = CSIIngestNode()
        out = node({"caller_trust_level": TRUST, "user_input": _VALID_CSI_FRAME})
        assert out["status"] == AgentStatus.SUCCESS.value
        assert out["zone_snapshot"]
