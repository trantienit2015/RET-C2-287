"""State schema for RET-C2-287 — Retail Store Spatial Occupancy & Customer Flow Anomaly Alert (WiFi CSI).

Flat TypedDict extending AgentState. Only agent-specific fields declared here; shared fields inherited.
All fields flat / JSON-serializable — no Pydantic, dataclasses, credentials, or InvocationContext
(S-5 + #8). **APPI-safe**: state carries zone-level data only — NO device identifiers / MAC / personal
data are ever stored.
"""

from __future__ import annotations

from typing import NotRequired

from framework.schemas.agent_state import AgentState


# Type-check note: the wheel ships no py.typed, so mypy resolves AgentState to Any
# and reports every NotRequired below as valid-type. The fields are correct (the state
# contract requires NotRequired) -- the report is a packaging artifact, suppressed per field.
# Drop these ignores once the wheel ships py.typed.
class RETC2287State(AgentState):
    # --- CSIIngest (pre_process) output ---
    # Normalized zone telemetry (vendor-agnostic): {store_id, timestamp, vendor, zones: [{zone_id, rssi, frame_count}]}
    zone_snapshot: NotRequired[dict]  # type: ignore[valid-type]

    # --- ZoneOccupancyParse (inner) output ---
    # Per-zone occupancy estimate: [{zone_id, occupancy, flow_rate, hour_of_day, weekday}]
    occupancy_vector: NotRequired[list[dict]]  # type: ignore[valid-type]

    # --- BaselineRetrieve (inner) output ---
    # Per-zone rolling baseline: {zone_id: {mean, std, sample_days}}
    baselines: NotRequired[dict]  # type: ignore[valid-type]

    # --- AnomalyScoreCompute (inner) output ---
    #   {zone_id, occupancy, z_score}
    anomaly_scores: NotRequired[list[dict]]  # type: ignore[valid-type]

    # --- FlowAnomalyClassify (inner) output ---
    #   {zone_id, anomaly_type: "CROWD"|"EMPTY"|"OCCUPANCY_DROP"|"QUEUE_OVERFLOW"|"NORMAL", severity, z_score}
    anomaly_classifications: NotRequired[list[dict]]  # type: ignore[valid-type]

    # --- AlertPayloadBuild (inner) output ---
    alert_payload: NotRequired[dict]  # type: ignore[valid-type]  # versioned JSON alert (schema 1.0), zone-level only

    # --- AlertDispatch (post_process) output ---
    delivery_receipts: NotRequired[list[dict]]  # type: ignore[valid-type]  # {channel, status, reason}
