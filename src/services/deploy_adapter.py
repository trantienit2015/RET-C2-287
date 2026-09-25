"""AgentCore Platform v1.0 — RET-C2-287 deploy-time resource adapter (production wiring).

Why it exists: the deployed endpoint built `Graph()` with no
`baseline_store` and no alert `dispatcher`, so every zone scored NORMAL (empty baseline →
std=0 → z=0) and alerts were only ever 'queued', never sent. This adapter builds the two
production resources the agent needs and fails fast when they are absent.

Contract:
  - `build_baseline_store(secrets, *, allow_stub=False)` — returns the rolling-baseline
    lookup dict from the configured store (`BASELINE_STORE_API_KEY` / `BASELINE_STORE_URL`
    via `ctx.secrets`). Production mandatory: a missing key/URL raises `DeployConfigError`
    (never serve an empty baseline that silently classifies everything NORMAL).
  - `build_dispatcher(secrets, *, allow_stub=False)` — returns an object exposing
    `send(url, payload) -> dict` (the interface `services.alert.dispatch` calls) that
    performs the real egress send (`ALERT_DISPATCH_TOKEN`); production mandatory.
  - Stub path (`allow_stub=True` + `RET_C2_287_ALLOW_STUB_DEPLOY` or `STG_MOCK_MODE`): returns
    an empty baseline / `None` dispatcher for local/demo runs and the in-job CI STG deploy
    (opt-in only).

Secrets flow only through the injected provider; never `os.environ`, never in State.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

_DEFAULT_TIMEOUT_S = 10.0
_STUB_ENV_FLAG = "RET_C2_287_ALLOW_STUB_DEPLOY"
# Set by the CI deploy-stg job (in-job provisional deploy: no real secrets, no egress).
_STG_MOCK_ENV_FLAG = "STG_MOCK_MODE"


class DeployConfigError(RuntimeError):
    """Raised when a required deploy-time resource is not configured for production."""


class DeployRequestError(RuntimeError):
    """Raised when a live deploy-time resource request fails (network/HTTP/decode)."""


def _stub_enabled(allow_stub: bool) -> bool:
    """The stand-in needs BOTH the caller opt-in and an explicit non-production env signal."""
    return allow_stub and any(
        os.environ.get(flag, "").lower() in ("1", "true", "yes") for flag in (_STUB_ENV_FLAG, _STG_MOCK_ENV_FLAG)
    )


def build_baseline_store(secrets: Any, *, allow_stub: bool = False) -> dict[str, Any]:
    """Fetch the rolling-baseline store from the configured provider."""
    if _stub_enabled(allow_stub):
        return {}

    if secrets is None:
        raise DeployConfigError("no secret provider bound; cannot load the production baseline store")

    try:
        api_key = secrets.require("BASELINE_STORE_API_KEY")
    except Exception as exc:  # noqa: BLE001
        raise DeployConfigError(
            "live baseline store requires BASELINE_STORE_API_KEY (declared in agent.yaml "
            "requires.secrets); set it, or opt into the demo stub explicitly"
        ) from exc
    if not api_key:
        raise DeployConfigError("BASELINE_STORE_API_KEY is empty; a live baseline store key is required")

    base_url = ""
    try:
        base_url = secrets.require("BASELINE_STORE_URL")
    except Exception:  # noqa: BLE001
        base_url = os.environ.get("BASELINE_STORE_URL", "")
    if not base_url:
        raise DeployConfigError("BASELINE_STORE_URL is not configured; the baseline store endpoint is required")

    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/baselines",
        method="GET",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_DEFAULT_TIMEOUT_S) as resp:
            store = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as exc:
        raise DeployRequestError(f"baseline store fetch failed: {exc}") from exc
    if not isinstance(store, dict) or not store:
        raise DeployRequestError("baseline store returned an empty/invalid payload")
    return store


class HttpAlertDispatcher:
    """Live alert egress transport.

    Exposes the exact interface `services.alert.dispatch` invokes — `send(url, payload)`.
    Keeping the contract as a named class (rather than a bare callable) makes the
    consumer/producer mismatch a construction-time type error instead of a runtime
    `AttributeError` that an exception handler can absorb into a 'failed' receipt.
    """

    def __init__(self, token: str, timeout_s: float = _DEFAULT_TIMEOUT_S) -> None:
        self._token = token
        self._timeout_s = timeout_s

    def send(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout_s) as resp:
                return {"status": "sent", "http_status": resp.status}
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            raise DeployRequestError(f"alert dispatch to {url} failed: {exc}") from exc


def build_dispatcher(secrets: Any, *, allow_stub: bool = False) -> Any:
    """Build the real alert egress dispatcher, or None in the opt-in stub.

    Returns an object with `send(url, payload)` — see `HttpAlertDispatcher`.
    """
    if _stub_enabled(allow_stub):
        return None

    if secrets is None:
        raise DeployConfigError("no secret provider bound; cannot build the production alert dispatcher")

    try:
        token = secrets.require("ALERT_DISPATCH_TOKEN")
    except Exception as exc:  # noqa: BLE001
        raise DeployConfigError(
            "live alert dispatch requires ALERT_DISPATCH_TOKEN (declared in agent.yaml "
            "requires.secrets); set it, or opt into the demo stub explicitly"
        ) from exc
    if not token:
        raise DeployConfigError("ALERT_DISPATCH_TOKEN is empty; a live dispatch token is required")

    return HttpAlertDispatcher(token)
