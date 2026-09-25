"""ZoneOccupancyParseNode (inner step_a) — RSSI → per-zone occupancy + flow rate.

First node of the Cat 2 inner subgraph. Parses the JSON zone snapshot (validated_input) and estimates
per-zone occupancy + flow rate via services/csi.estimate_occupancy. Coefficients injected via config.

Node contract: execute(self, state) -> dict; partial update; status is an AgentStatus enum.
"""

from __future__ import annotations

import json

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.trust_level import TrustLevel
from framework.schemas.agent_status import AgentStatus
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import RETC2287State
from src.services.csi import estimate_occupancy


class ZoneOccupancyParseNode(FunctionNode):
    """Estimate per-zone occupancy + flow rate from the zone snapshot."""

    # S-1: inner-subgraph node — caller trust is verified at the outer
    # backbone; declaring least-privilege ANONYMOUS here (inner nodes never re-gate).
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def __init__(self, occupancy_coeff: Any = None) -> None:
        self._coeff = occupancy_coeff or {}

    def execute(self, state: RETC2287State) -> dict[str, Any]:
        emit_trace_event("zone_occupancy_parsed", {"correlation_id": state.get("correlation_id")}, state)
        raw = state.get("user_input", "")
        try:
            snapshot = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            snapshot = None
        if not isinstance(snapshot, dict) or not snapshot.get("zones"):
            return {"status": AgentStatus.ERROR.value, "error_log": ["zone_occupancy: invalid inner input"]}

        vector = estimate_occupancy(snapshot, self._coeff)
        if not vector:
            return {"status": AgentStatus.ERROR.value, "error_log": ["zone_occupancy: no zones estimated"]}

        return {"zone_snapshot": snapshot, "occupancy_vector": vector, "status": AgentStatus.SUCCESS.value}
