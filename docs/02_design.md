# RET-C2-287 — Design Specification

## Position in AgentCore Architecture

- **Agent Class**: `RETC2287Graph` (alias `Graph`) in `src/graph/graph.py`
- **L1 Base**: `AgentBaseGraph` (L1 direct inheritance — no L2 base agent inheritance)
- **Category**: Cat 2 (multi-step domain workflow) · **Pattern**: VectorRAG anomaly-detection pipeline
- **Three-Layer Separation**:
  - **State** (`src/schemas/state.py`): `RETC2287State(AgentState)` — flat TypedDict, JSON-serializable
    primitives only; **APPI-safe** (zone-level only, no device identifiers); no Pydantic/dataclass/ctx.
  - **Node**: each node inherits `FunctionNode`, overrides `execute(self, state) -> dict` only; partial
    update + `status = AgentStatus.*` enum. No `_invoke_impl`, no `__call__` override.
  - **Graph**: `register_nodes()` calls `super().register_nodes()` then fills the 3 slots; `add_edges()`
    not overridden.

## Cat 2 Architecture (outer backbone + GraphNode + inner subgraph)

```
OUTER (AgentBaseGraph — src/graph/graph.py):
  initialize → pre_process(CSIIngest) → main(OccupancyAnomalyGraphNode) → post_process(AlertDispatch) → finalize
                                            │ get_subgraph().invoke(validated_input JSON, ctx)
                                            ▼
INNER (BaseGraph — src/graph/domain_workflow_graph.py):
  START → zone_occupancy_parse → baseline_retrieve → anomaly_score_compute → flow_anomaly_classify → alert_payload_build → END
```

## Node mapping (7 design steps → 5-node backbone)

| Slot | Node | Role | Output |
|---|---|---|---|
| pre_process | `CSIIngestNode` | S-1 INTERNAL trust; parse + vendor-normalize CSI frame; **fail-fast unknown vendor** | `zone_snapshot` |
| main → inner a | `ZoneOccupancyParseNode` | RSSI → per-zone occupancy + flow rate | `occupancy_vector` |
| main → inner b | `BaselineRetrieveNode` | 4-week rolling baseline per zone × hour × weekday; S-4 audit | `baselines` |
| main → inner c | `AnomalyScoreComputeNode` | Z-score per zone vs baseline (configurable σ) | `anomaly_scores` |
| main → inner d | `FlowAnomalyClassifyNode` | CROWD / EMPTY / OCCUPANCY_DROP / NORMAL + severity | `anomaly_classifications` |
| main → inner e | `AlertPayloadBuildNode` | versioned (schema 1.0) **APPI-safe** alert (zone-level only) | `alert_payload` |
| post_process | `AlertDispatchNode` | **S-3 webhook allowlist gate** + multi-channel dispatch; S-4 audit | `delivery_receipts`, `formatted_output` |

Deterministic compute lives in `src/services/` (`csi.py`, `anomaly.py`, `alert.py`).

## Error propagation (inner linear topology)

Inner `BaseGraph` linear edges → every node runs; downstream nodes short-circuit (`status==ERROR`
passthrough). All-NORMAL → empty alert payload → AlertDispatch is a clean SUCCESS no-op. Verified:
unknown vendor + empty input both end `status=error`.

## Security (5-layer)

- **S-1**: `required_trust_level: INTERNAL` (agent.yaml) + `CSIIngestNode.required_trust_level =
  TrustLevel.INTERNAL`; store telemetry is internal-only.
- **APPI-safe**: state + alert payload carry zone-level data only (store_id + zone_id + occupancy/severity)
  — never device identifiers / MAC addresses.
- **S-3 egress gate**: `AlertDispatch` checks every channel's `webhook_url` against the configured
  `alert_routing.allowlist` (deterministic, fail-closed — empty allowlist allows nothing); a disallowed
  URL is dropped + logged, never sent. Plain post-processing logic, NOT a developer security-gate method.
  Secrets via `bound_secrets()`/`secrets_factory()`/`provision_secrets()`; never `os.environ`.
- **S-4**: `emit_trace_event()` in BaselineRetrieve + AlertDispatch.
- **S-5**: no credentials in source/state; flat msgpack-safe state.

## Scope & config

IN — CSI frame parse → occupancy → baseline → Z-score → classify → APPI-safe alert build + S-3-gated
multi-channel dispatch. DEFERRED — the daily baseline-ingestion pipeline (external, config-referenced),
vendor webhook/adapter integration (config surface), per-channel SLA tuning. Baseline store + vendor
strategies + occupancy coefficients + σ + alert_routing injected via config.
