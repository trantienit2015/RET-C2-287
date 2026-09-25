"""AlertDispatchNode (outer post_process) — S-3 egress-gated multi-channel dispatch + S-4 audit.

Design step 7. Routes the alert payload to the configured channels (Slack / LINE Works / POS /
webhook) AFTER an S-3 egress gate: every channel's `webhook_url` must be in the configured allowlist
(deterministic, fail-closed) — a disallowed URL is dropped and logged, never sent (services/alert.dispatch).
This is plain deterministic post-processing logic, NOT a developer security-gate method. Emits S-4 audit.

When there is no alert payload (all-NORMAL) the node is a clean SUCCESS no-op. If channels are configured
but ALL are dropped by the allowlist, that is surfaced in the receipts (not a silent pass).

Node contract: execute(self, state) -> dict; partial update; status is AgentStatus.<X>.value (criterion #15).
"""

from __future__ import annotations

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.trust_level import TrustLevel
from framework.schemas.agent_status import AgentStatus
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import RETC2287State
from src.services.alert import dispatch


class AlertDispatchNode(FunctionNode):
    """S-3 egress-gated dispatch of the alert to configured channels."""

    # S-1: outer post_process node handling internal CSI/alert data —
    # matches agent.yaml required_trust_level (INTERNAL).
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.INTERNAL

    def __init__(self, alert_routing: Any = None, dispatcher: Any = None) -> None:
        self._routing = alert_routing or {}
        self._dispatcher = dispatcher

    def execute(self, state: RETC2287State) -> dict[str, Any]:
        payload = state.get("alert_payload", {})
        if not payload:
            # all-NORMAL / below threshold — nothing to dispatch.
            return {
                "delivery_receipts": [],
                "formatted_output": {"alert": None, "delivery_receipts": []},
                "status": AgentStatus.SUCCESS.value,
            }

        receipts = dispatch(payload, self._routing, self._dispatcher)
        emit_trace_event(
            "alert_dispatch",
            # Audit counts must not conflate outcomes: 'queued' means no dispatcher was
            # configured, i.e. NOT sent. Counting it as delivered reported success for
            # undelivered alerts.
            {
                "max_severity": payload.get("max_severity"),
                "delivered": sum(1 for r in receipts if r["status"] == "delivered"),
                "queued": sum(1 for r in receipts if r["status"] == "queued"),
                "failed": sum(1 for r in receipts if r["status"] == "failed"),
                "dropped": sum(1 for r in receipts if r["status"] == "dropped"),
            },
            state,
        )

        return {
            "delivery_receipts": receipts,
            "formatted_output": {"alert": payload, "delivery_receipts": receipts},
            "status": AgentStatus.SUCCESS.value,
        }
