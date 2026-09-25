# RET-C2-287 — Test Specification

## Test layout

- `tests/unit/` — per-node + services + security (S-1 gate)
- `tests/integration/` — full graph `compile()` + `invoke()`
- `tests/proof_of_boundary/` — state safety + import isolation

## Test cases (TC)

| TC-ID | Test | File | Expected |
|---|---|---|---|
| TC-01 | State flat `AgentState` subtype; no Pydantic/credential fields | `proof_of_boundary/test_state_safety.py` | 0 violations |
| TC-02 | Empty / unknown-vendor input → `status=ERROR` | `unit/test_nodes.py` + integration | ERROR |
| TC-03 | No credentials in source/state | `proof_of_boundary/*` + S-5 CI | pass |
| TC-04 | Secrets via provider pattern (entry point), not `os.environ` | `src/api/server.py` (review) | pass |
| TC-05 | `emit_trace_event()` for side-effect nodes (baseline-retrieve / alert-dispatch) | code review + S-4 | pass |
| TC-06 | Nodes stateless; data flows through state | node design | pass |
| TC-07 | No `_invoke_impl`; `execute(self, state)` only | node contract | pass |
| TC-08 | S-1 trust gate: `CSIIngestNode.required_trust_level = INTERNAL` blocks ANONYMOUS | `unit/test_security.py` | ERROR via `__call__` |

## Node + services unit coverage

| Unit | Success | Error/edge |
|---|---|---|
| `CSIIngestNode` | vendor parse | **unknown vendor → ERROR**; empty → ERROR |
| `ZoneOccupancyParseNode` | RSSI → occupancy + weekday carried | — |
| `BaselineRetrieveNode` | zone×hour×weekday bucket lookup | upstream-error passthrough |
| `AnomalyScoreComputeNode` | Z-score | std≤0 → 0 |
| `FlowAnomalyClassifyNode` | CROWD/EMPTY/NORMAL | — |
| `AlertPayloadBuildNode` | **APPI-safe** alert (no rssi/device) | all-NORMAL → empty payload |
| `AlertDispatchNode` | **S-3 allowlist gate** (allowed→queued, disallowed→dropped) | no payload → no-op SUCCESS |
| services | csi parse/occupancy / baseline+zscore+classify / build+url_allowed+dispatch | — |

## Proof-of-Boundary (PB)

| PB-ID | Boundary | Test |
|---|---|---|
| PB-2/5 | State serialization safety (no device IDs) | `test_state_safety.py` |
| PB-4 | Import isolation (no agenticstar/Level 0) | `test_import_isolation.py` |
| PB-1 | S-1 trust gate blocks under-trusted caller | `unit/test_security.py` |
| PB-6 | Full pipeline compile + invoke → initialize→pre→main→post→finalize | `integration::test_backbone_node_history` |

## Domain-specific assertions

- **S-3 egress gate**: a non-allowlisted `webhook_url` is dropped (never dispatched); an allowlisted one is
  queued/delivered (`test_nodes.py`, `test_services.py`, `integration::test_crowd_alert_with_s3_gate`).
- **APPI-safe**: the alert payload contains no `rssi`/device data — zone-level only (`test_nodes.py`,
  integration).
- **Anomaly classification**: a high Z-score → CROWD/critical; normal → no alert (`test_*`, integration).
- **Fail-fast**: an unknown CSI vendor → explicit error (no silent empty parse).

## Run

```bash
python -m pytest tests/ -v
ruff check src/ tests/
```
