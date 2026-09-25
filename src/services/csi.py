"""Deterministic WiFi-CSI parsing + occupancy estimation for RET-C2-287.

Pure logic, no LLM, no secrets. Vendor frame layouts (Cisco / Aruba / Ruckus / generic) are handled by
a strategy map injected/extended via config; the RSSI→occupancy coefficients come from config too.
APPI-safe: only zone-level aggregates are produced — never device identifiers / MAC addresses.

- ``parse_frame(frame, vendor_strategies)`` — normalize a vendor CSI frame → zone telemetry; raises
  ValueError on an unknown vendor (fail-fast, not a silent empty parse).
- ``estimate_occupancy(zone_snapshot, coeff)`` — RSSI → per-zone occupancy + flow rate.
"""

from __future__ import annotations

from typing import Any

_KNOWN_VENDORS = ("cisco", "aruba", "ruckus", "generic")


def parse_frame(frame: dict[str, Any], vendor_strategies: Any = None) -> dict[str, Any]:
    """Normalize a vendor CSI frame into vendor-agnostic zone telemetry. Raises ValueError on unknown vendor."""
    if not isinstance(frame, dict):
        raise ValueError("csi frame must be an object")
    vendor = str(frame.get("vendor", "")).lower()
    known = set(_KNOWN_VENDORS) | set((vendor_strategies or {}).keys())
    if vendor not in known:
        raise ValueError(f"unknown CSI vendor '{vendor}' (known: {sorted(known)})")

    readings = frame.get("zone_readings") or []
    zones = []
    for r in readings:
        if not isinstance(r, dict) or not r.get("zone_id"):
            continue
        zones.append(
            {
                "zone_id": str(r["zone_id"]),
                "rssi": float(r.get("rssi", 0) or 0),
                "frame_count": int(r.get("frame_count", 0) or 0),
            }
        )
    return {
        "store_id": str(frame.get("store_id", "")),
        "timestamp": str(frame.get("timestamp", "")),
        "weekday": int(frame.get("weekday", 0) or 0),  # carried through for baseline (zone×hour×weekday)
        "vendor": vendor,
        "zones": zones,
    }


def estimate_occupancy(zone_snapshot: dict[str, Any], coeff: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """RSSI → per-zone occupancy estimate + flow rate. coeff: {rssi_to_count, flow_divisor}."""
    coeff = coeff or {}
    rssi_to_count = float(coeff.get("rssi_to_count", 0.1))
    flow_divisor = float(coeff.get("flow_divisor", 60.0)) or 60.0
    hour = (
        int((zone_snapshot.get("timestamp", "") or "T00")[11:13] or 0)
        if len(zone_snapshot.get("timestamp", "")) >= 13
        else 0
    )
    weekday = int(zone_snapshot.get("weekday", 0) or 0)

    out = []
    for z in zone_snapshot.get("zones", []):
        # simple deterministic occupancy proxy: stronger aggregate RSSI presence + frame volume
        occupancy = max(0.0, round(abs(z.get("rssi", 0.0)) * rssi_to_count, 2))
        flow_rate = round(z.get("frame_count", 0) / flow_divisor, 2)
        out.append(
            {
                "zone_id": z["zone_id"],
                "occupancy": occupancy,
                "flow_rate": flow_rate,
                "hour_of_day": hour,
                "weekday": weekday,
            }
        )
    return out
