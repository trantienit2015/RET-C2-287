"""Deterministic baseline retrieval + Z-score + flow-anomaly classification for RET-C2-287.

Pure logic, no LLM, no secrets. The 4-week rolling baseline store is injected from config (keyed by
zone × hour × weekday); a vector store is wired at deploy, this dependency-free lookup keeps the
pipeline runnable + testable. Classification thresholds (σ) come from config.

- ``retrieve_baselines(occupancy_vector, baseline_store)`` — per-zone {mean,std,sample_days} for the
  matching (zone, hour, weekday) bucket.
- ``compute_zscores(occupancy_vector, baselines)`` — Z-score per zone vs its baseline.
- ``classify(scores, occupancy_vector, sigma)`` — typed anomaly + severity.
"""

from __future__ import annotations

from typing import Any


def _bucket_key(zone_id: str, hour: int, weekday: int) -> str:
    return f"{zone_id}|{hour}|{weekday}"


def retrieve_baselines(occupancy_vector: list[dict[str, Any]], baseline_store: dict[str, Any]) -> dict[str, Any]:
    """Look up the rolling baseline for each zone's (zone, hour, weekday) bucket."""
    store = baseline_store or {}
    out: dict[str, Any] = {}
    for o in occupancy_vector or []:
        key = _bucket_key(o["zone_id"], o.get("hour_of_day", 0), o.get("weekday", 0))
        b = store.get(key) or store.get(o["zone_id"]) or {}
        out[o["zone_id"]] = {
            "mean": float(b.get("mean", 0.0)),
            "std": float(b.get("std", 0.0)),
            "sample_days": int(b.get("sample_days", 0)),
        }
    return out


def compute_zscores(occupancy_vector: list[dict[str, Any]], baselines: dict[str, Any]) -> list[dict[str, Any]]:
    """Z-score per zone vs baseline (std<=0 → 0, treated as insufficient baseline)."""
    out = []
    for o in occupancy_vector or []:
        b = baselines.get(o["zone_id"], {})
        std = float(b.get("std", 0.0))
        mean = float(b.get("mean", 0.0))
        z = round((o["occupancy"] - mean) / std, 3) if std > 0 else 0.0
        out.append(
            {"zone_id": o["zone_id"], "occupancy": o["occupancy"], "z_score": z, "flow_rate": o.get("flow_rate", 0.0)}
        )
    return out


def classify(scores: list[dict[str, Any]], sigma: float = 2.0) -> list[dict[str, Any]]:
    """Classify each zone's deviation into a typed anomaly + severity."""
    out = []
    for s in scores or []:
        z = s.get("z_score", 0.0)
        if abs(z) < sigma:
            atype, severity = "NORMAL", "info"
        elif z >= sigma * 1.5:
            # (Same root cause as the OCCUPANCY_DROP branch below): `flow_rate` is a
            # single-frame count with no historical baseline, so it cannot distinguish a
            # stalled queue from ordinary low movement. A severe positive occupancy z-score
            # is reported as CROWD; the sub-type is carried as an advisory hint only, never
            # as a distinct baselined anomaly class.
            atype, severity = "CROWD", "critical"
        elif z >= sigma:
            atype, severity = "CROWD", "warning"
        elif z <= -sigma * 1.5:
            atype, severity = "EMPTY", "warning"
        else:  # z <= -sigma
            # this branch fires on a negative OCCUPANCY z-score, not an
            # independently-baselined flow metric (flow_rate is a single-frame
            # count with no historical baseline). Label it for what is actually
            # measured — an occupancy drop — rather than the unsupported FLOW_DROP.
            atype, severity = "OCCUPANCY_DROP", "warning"
        out.append({"zone_id": s["zone_id"], "anomaly_type": atype, "severity": severity, "z_score": z})
    return out
