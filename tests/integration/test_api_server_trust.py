# RET-C2-287 — HTTP-layer tests for the standalone /invoke adapter.
#
# The audit finding was in the HTTP adapter itself (`request.state.trust_level` absent →
# defaulted to INTERNAL, i.e. fail-open). Node-level trust tests cannot cover that: they
# never construct the FastAPI context. These tests drive the real ASGI app so the default
# applied by `src/api/server.py` is the thing under test.

import json
import os

import pytest

fastapi_testclient = pytest.importorskip("fastapi.testclient", reason="fastapi not installed")

# The server builds its production resources at import time and is deliberately
# fail-closed; opt into the demo stub so the adapter itself can be exercised.
os.environ.setdefault("RET_C2_287_ALLOW_STUB_DEPLOY", "1")

from src.api import server as server_module  # noqa: E402

_FRAME = json.dumps({
    "vendor": "cisco", "store_id": "S001", "timestamp": "2026-06-16T14:30:00", "weekday": 2,
    "zone_readings": [{"zone_id": "Z1", "rssi": 12, "frame_count": 120}],
})


@pytest.fixture()
def client():
    return fastapi_testclient.TestClient(server_module.app)


class TestInvokeTrustBoundary:
    def test_unauthenticated_request_is_not_treated_as_internal(self, client):
        """no auth middleware ran → the caller must be ANONYMOUS, and CSIIngestNode
        (INTERNAL) must refuse it at the S-1 gate rather than ingesting CSI telemetry."""
        r = client.post("/invoke", json={"input": _FRAME, "session_id": "s-anon"})
        assert r.status_code == 200  # the adapter answers; the *gate* is what rejects
        body = r.json()
        assert body.get("status") in ("error", "ERROR"), body
        # The run terminated at the gated node — no zone data was ever produced.
        assert body.get("output") is None, body
        assert not body.get("formatted_output"), body

    def test_authenticated_internal_caller_is_admitted(self):
        """A middleware-populated INTERNAL caller passes the same gate.

        Middleware cannot be added to an already-started app, so the trust attribute is set
        directly on the ASGI scope's request state via a raw header-driven scope hook — this
        mirrors what the AgentGateway middleware does upstream of this adapter.
        """
        from framework.schemas.trust_level import TrustLevel

        app = server_module.app

        class _TrustScope:
            def __init__(self, inner):
                self.inner = inner

            async def __call__(self, scope, receive, send):
                if scope["type"] == "http":
                    scope.setdefault("state", {})
                    scope["state"]["trust_level"] = TrustLevel.INTERNAL
                    scope["state"]["caller_id"] = "store1"
                await self.inner(scope, receive, send)

        with fastapi_testclient.TestClient(_TrustScope(app)) as authed:
            r = authed.post("/invoke", json={"input": _FRAME, "session_id": "s-auth"})
        assert r.status_code == 200
        body = r.json()
        # Admitted: execution proceeded past the INTERNAL-gated ingest node.
        assert "CSIIngestNode" in body.get("node_history", []), body
        assert body.get("status") in ("success", "SUCCESS"), body

    def test_health_is_open(self, client):
        assert client.get("/health").json()["status"] == "ok"
