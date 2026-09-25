"""AlertPayloadBuildNode (inner step_e) — build the APPI-safe versioned alert payload.

Fifth node of the Cat 2 inner subgraph. Builds the versioned JSON alert (schema 1.0) from the anomaly
classifications meeting `min_severity`, zone-level only (NO device identifiers — APPI-safe), via
services/alert.build_alert. (5-minute suppression dedup is applied by the dispatcher/store in production;
here the payload is built deterministically.)

Node contract: execute(self, state) -> dict; partial update; status is an AgentStatus enum.
"""

from __future__ import annotations

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.trust_level import TrustLevel
from framework.schemas.agent_status import AgentStatus
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import RETC2287State
from src.services.alert import build_alert


class AlertPayloadBuildNode(FunctionNode):
    """Build the APPI-safe alert payload (zone-level only)."""

    # S-1: inner-subgraph node — caller trust is verified at the outer
    # backbone; declaring least-privilege ANONYMOUS here (inner nodes never re-gate).
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def __init__(self, min_severity: str = "warning"):
        self._min_severity = min_severity

    def execute(self, state: RETC2287State) -> dict[str, Any]:
        emit_trace_event("alert_payload_built", {"correlation_id": state.get("correlation_id")}, state)
        if state.get("status") in (AgentStatus.ERROR.value, AgentStatus.ERROR.value):
            return {"status": AgentStatus.ERROR.value}  # short-circuit: an upstream inner step already errored
        store_id = state.get("zone_snapshot", {}).get("store_id", "")
        payload = build_alert(store_id, state.get("anomaly_classifications", []), self._min_severity)
        # an empty payload (all NORMAL / below threshold) is a valid SUCCESS — no alert to send.
        return {"alert_payload": payload, "status": AgentStatus.SUCCESS.value}
