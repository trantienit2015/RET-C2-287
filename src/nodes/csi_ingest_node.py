"""CSIIngestNode (outer pre_process) — parse + vendor-normalize the WiFi-CSI frame.

Design step 1. Parses the raw CSI frame into vendor-agnostic zone telemetry via services/csi.
parse_frame (Cisco/Aruba/Ruckus/generic strategy), fails fast on an unknown vendor (explicit error, not
a silent empty parse), and serializes the snapshot into validated_input (JSON string) for the Cat 2
inner subgraph. Store telemetry is internal-only (S-1): require INTERNAL trust. APPI-safe — zone-level
only, no device identifiers.

Node contract: execute(self, state) -> dict; partial update; status is an AgentStatus enum.
"""

from __future__ import annotations

from typing import Any
import json

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import RETC2287State
from src.services.csi import parse_frame


class CSIIngestNode(FunctionNode):
    """Parse + vendor-normalize the CSI frame into zone telemetry."""

    required_trust_level = TrustLevel.INTERNAL

    def __init__(self, vendor_strategies: Any = None) -> None:
        self._vendor_strategies = vendor_strategies or {}

    def execute(self, state: RETC2287State) -> dict[str, Any]:
        # S-4: domain audit event on every path (no device identifiers — APPI-safe).
        emit_trace_event("csi_frame_received", {"correlation_id": state.get("correlation_id")}, state)
        raw = state.get("user_input", "")
        if isinstance(raw, str):
            raw = raw.strip()
            if not raw:
                return {"status": AgentStatus.ERROR.value, "error_log": ["Empty input — CSI frame (JSON) required"]}
            try:
                frame = json.loads(raw)
            except (ValueError, TypeError):
                return {"status": AgentStatus.ERROR.value, "error_log": ["Input is not valid JSON CSI frame"]}
        else:
            frame = raw

        try:
            snapshot = parse_frame(frame, self._vendor_strategies)
        except ValueError as exc:
            return {"status": AgentStatus.ERROR.value, "error_log": [f"CSI ingest failed: {exc}"]}

        if not snapshot.get("zones"):
            return {"status": AgentStatus.ERROR.value, "error_log": ["CSI frame has no zone readings"]}

        return {
            "zone_snapshot": snapshot,
            "validated_input": json.dumps(snapshot, ensure_ascii=False),
            "status": AgentStatus.SUCCESS.value,
        }
