"""Deterministic alert payload build + S-3 egress allowlist dispatch for RET-C2-287.

Pure logic, no secrets. APPI-safe: the payload contains zone-level data only (no device IDs).

- ``build_alert(store_id, classifications, min_severity)`` — versioned JSON alert (schema 1.0) with the
  anomalous zones meeting min_severity. Returns {} when nothing qualifies.
- ``url_allowed(url, allowlist)`` — S-3 egress guard: a webhook URL must be in the configured allowlist
  before any dispatch (deterministic, non-bypassable).
- ``dispatch(payload, routing, dispatcher)`` — route to configured channels, dropping any channel whose
  webhook_url is not allowlisted (logged as a drop), returning delivery receipts.
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import urlparse

_SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


def build_alert(store_id: str, classifications: list[dict[str, Any]], min_severity: str = "warning") -> dict[str, Any]:
    threshold = _SEVERITY_ORDER.get(min_severity, 1)
    anomalies = [
        c
        for c in (classifications or [])
        if c.get("anomaly_type") != "NORMAL" and _SEVERITY_ORDER.get(cast(str, c.get("severity")), 0) >= threshold
    ]
    if not anomalies:
        return {}
    return {
        "schema_version": "1.0",
        "store_id": store_id,  # zone-level only — NO device identifiers
        "anomalies": anomalies,
        "max_severity": max((c["severity"] for c in anomalies), key=lambda s: _SEVERITY_ORDER.get(s, 0)),
    }


def url_allowed(url: str, allowlist: Any) -> bool:
    """S-3 egress guard: exact-host allowlist match. Empty allowlist → nothing allowed (fail-closed)."""
    if not url or not allowlist:
        return False
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return False
    allowed_hosts = set()
    for a in allowlist:
        try:
            allowed_hosts.add(urlparse(a).hostname or a)
        except ValueError:
            allowed_hosts.add(a)
    return host in allowed_hosts


def dispatch(payload: dict[str, Any], routing: dict[str, Any], dispatcher: Any = None) -> list[dict[str, Any]]:
    """Dispatch the alert to configured channels, S-3-gating each webhook_url against the allowlist.

    routing: {channels: [{name, webhook_url}], allowlist: [url|host]}. `dispatcher` (optional) actually
    sends; absent it, an allowed channel is recorded as 'queued' (no real network call in tests).

    A supplied `dispatcher` MUST expose `send(url, payload)`. A dispatcher missing that method is a
    wiring defect, not a per-channel delivery failure: it raises `TypeError` immediately rather than
    being recorded as a 'failed' receipt for every channel (which is how a production egress
    misconfiguration previously masqueraded as a transport error).
    """
    receipts: list[dict[str, Any]] = []
    allowlist = (routing or {}).get("allowlist", [])
    if dispatcher is not None and not callable(getattr(dispatcher, "send", None)):
        raise TypeError(
            "alert dispatcher must expose send(url, payload); got "
            f"{type(dispatcher).__name__} without a callable .send"
        )
    for ch in (routing or {}).get("channels", []):
        name = ch.get("name", "")
        url = ch.get("webhook_url", "")
        if not url_allowed(url, allowlist):
            receipts.append({"channel": name, "status": "dropped", "reason": "webhook_url not in S-3 allowlist"})
            continue
        if dispatcher is not None:
            try:
                dispatcher.send(url, payload)
                receipts.append({"channel": name, "status": "delivered", "reason": ""})
            except Exception as exc:  # noqa: BLE001
                receipts.append({"channel": name, "status": "failed", "reason": str(exc)})
        else:
            receipts.append({"channel": name, "status": "queued", "reason": "allowlisted; dispatcher not configured"})
    return receipts
