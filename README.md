# RET-C2-287 — Retail Store Spatial Occupancy & Customer Flow Anomaly Alert Agent (WiFi CSI)

> **Category**: Cat 2 (orchestrates multiple steps to accomplish a specific use case)
> **Industry**: RET

## Overview

Detects unusual occupancy in store zones from WiFi channel-state-information (CSI) telemetry and
builds a zone-level alert. The input is one JSON frame with a `vendor` (`cisco`, `aruba`,
`ruckus` or `generic`, plus any vendor added through configuration), `store_id`, `timestamp`,
`weekday` and a list of `zone_readings` (`zone_id`, `rssi`, `frame_count`). Empty input, input
that is not JSON, an unknown vendor or a frame with no zone readings is rejected. The entry node
requires an internal-level caller.

For each zone the agent estimates occupancy from the RSSI value and a flow rate from the frame
count using fixed, configurable coefficients (a simple deterministic proxy, not a trained
model). It looks up a rolling baseline (mean and standard deviation) for the zone, hour and
weekday, computes a z-score, and classifies the zone as NORMAL, CROWD, EMPTY or OCCUPANCY_DROP
with a severity; the threshold `sigma` (default 2.0) is configurable. A zone with no baseline,
or a baseline with zero deviation, scores 0 and is classified NORMAL. Zones at or above
`min_severity` (default `warning`) go into a versioned alert that carries only the store ID and
zone-level results, never device identifiers. The alert is sent to each configured channel whose
webhook host is on an allowlist; channels not on the allowlist are dropped, and an empty
allowlist allows nothing. No language model is used.

The bundled HTTP entry point builds the baseline store and the alert sender from three secrets
(`BASELINE_STORE_API_KEY`, `BASELINE_STORE_URL`, `ALERT_DISPATCH_TOKEN`) and refuses to start if
they are missing. Setting `STG_MOCK_MODE=true` or `RET_C2_287_ALLOW_STUB_DEPLOY=1` starts it
instead with an empty baseline and no sender, so every zone is classified NORMAL and no alert is
sent.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Without it, start-up fails immediately (see *Behaviour without the platform* below). Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Installed from PyPI as a dependency. |
| Python | 3.11 or later |

```bash
pip install -e .
```

### Behaviour without the platform

The framework is designed to run **only** on AGENTIC STAR. There is no fallback or degraded
mode. If the platform is unreachable or the SDK version does not match, the agent raises
`PlatformRequired` during graph compile / start-up preflight rather than starting in a partially
working state. This is intentional — a half-running agent is worse than one that refuses to start.

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection. Running the agent itself does not.

## Project Structure

```
src/          agent implementation (nodes, services, schemas)
tests/        unit, integration and boundary tests
config/       agent configuration
docs/         design and test specification
```

See `docs/02_design.md` for the design and `docs/03_test_spec.md` for the test specification.

## Customising

1. Adjust `config/` for your own environment and policies.
2. Replace the knowledge sources and sample data with your own.
3. Review the node implementations under `src/nodes/` for domain-specific logic.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.
