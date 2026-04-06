"""Tests for the unified /ws/realtime WebSocket endpoint.

Uses a lightweight FastAPI app that only mounts the realtime router, so
the suite doesn't pay the cost of importing the full ShieldOps API on
every run.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from shieldops.api.auth.service import create_access_token
from shieldops.api.ws.broadcaster import Broadcaster, get_broadcaster, reset_broadcaster
from shieldops.api.ws.realtime import router as realtime_router


@pytest.fixture
def app() -> FastAPI:
    reset_broadcaster()
    fastapi_app = FastAPI()
    fastapi_app.include_router(realtime_router)

    # Test-only helper: publish an event from inside the app's event loop
    # so WebSocket sends land on the correct anyio portal.
    @fastapi_app.post("/_test/publish")
    async def _publish(payload: dict) -> dict:
        org_id = payload.get("org_id", "")
        event = payload.get("event", {})
        delivered = await get_broadcaster().broadcast_to_org(org_id, event)
        return {"delivered": delivered}

    return fastapi_app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def _reset_broadcaster_fixture():
    reset_broadcaster()
    yield
    reset_broadcaster()


# ── Broadcaster unit tests ───────────────────────────────────────────


class TestBroadcaster:
    @pytest.mark.asyncio
    async def test_initial_stats(self):
        b = Broadcaster()
        stats = b.get_stats()
        assert stats["total_connections"] == 0
        assert stats["org_count"] == 0
        assert stats["per_org"] == {}

    @pytest.mark.asyncio
    async def test_broadcast_to_empty_org_is_noop(self):
        b = Broadcaster()
        delivered = await b.broadcast_to_org("org-x", {"type": "metric_update", "data": {}})
        assert delivered == 0

    @pytest.mark.asyncio
    async def test_envelope_preserves_explicit_event_dict(self):
        b = Broadcaster()
        envelope = b._coerce_envelope(
            {"type": "firewall_event", "data": {"decision": "allow"}}, None, "org-a"
        )
        assert envelope["type"] == "firewall_event"
        assert envelope["org_id"] == "org-a"
        assert envelope["data"]["decision"] == "allow"
        assert "ts" in envelope

    @pytest.mark.asyncio
    async def test_tenant_isolation_in_registry(self):
        """Broadcasting to org-a must not touch org-b's registry."""
        b = Broadcaster()

        class _FakeWS:
            def __init__(self) -> None:
                from starlette.websockets import WebSocketState

                self.sent: list[dict] = []
                self.client_state = WebSocketState.CONNECTED

            async def send_json(self, data):
                self.sent.append(data)

        ws_a = _FakeWS()
        ws_b = _FakeWS()
        conn_a = await b.subscribe("org-a", ws_a)  # type: ignore[arg-type]
        conn_b = await b.subscribe("org-b", ws_b)  # type: ignore[arg-type]
        assert conn_a is not None and conn_b is not None

        await b.broadcast_to_org("org-a", {"type": "new_situation", "data": {"id": 1}})

        assert len(ws_a.sent) == 1
        assert ws_a.sent[0]["type"] == "new_situation"
        assert ws_b.sent == []  # strict tenant isolation
        assert b.get_stats()["per_org"] == {"org-a": 1, "org-b": 1}

    @pytest.mark.asyncio
    async def test_broadcast_delivers_to_all_org_connections(self):
        b = Broadcaster()

        from starlette.websockets import WebSocketState

        class _FakeWS:
            def __init__(self) -> None:
                self.sent: list[dict] = []
                self.client_state = WebSocketState.CONNECTED

            async def send_json(self, data):
                self.sent.append(data)

        sockets = [_FakeWS() for _ in range(3)]
        for ws in sockets:
            await b.subscribe("org-a", ws)  # type: ignore[arg-type]

        delivered = await b.broadcast_to_org(
            "org-a", {"type": "agent_run_complete", "data": {"run_id": "r1"}}
        )
        assert delivered == 3
        assert all(len(s.sent) == 1 for s in sockets)

    @pytest.mark.asyncio
    async def test_disconnect_cleanup(self):
        b = Broadcaster()

        from starlette.websockets import WebSocketState

        class _FakeWS:
            def __init__(self) -> None:
                self.client_state = WebSocketState.CONNECTED

            async def send_json(self, data):
                pass

        ws = _FakeWS()
        conn = await b.subscribe("org-a", ws)  # type: ignore[arg-type]
        assert conn is not None
        assert b.get_stats()["total_connections"] == 1

        await b.unsubscribe(conn)
        stats = b.get_stats()
        assert stats["total_connections"] == 0
        assert "org-a" not in stats["per_org"]

    def test_singleton_helpers(self):
        reset_broadcaster()
        b1 = get_broadcaster()
        b2 = get_broadcaster()
        assert b1 is b2
        reset_broadcaster()
        assert get_broadcaster() is not b1


# ── WebSocket endpoint tests ─────────────────────────────────────────


class TestRealtimeEndpoint:
    def test_rejects_missing_token(self, client: TestClient):
        from starlette.websockets import WebSocketDisconnect

        with client.websocket_connect("/ws/realtime") as ws:
            with pytest.raises(WebSocketDisconnect) as exc_info:
                ws.receive_json()
            assert exc_info.value.code == 4001

    def test_rejects_invalid_token(self, client: TestClient):
        from starlette.websockets import WebSocketDisconnect

        with client.websocket_connect("/ws/realtime?token=garbage") as ws:
            with pytest.raises(WebSocketDisconnect) as exc_info:
                ws.receive_json()
            assert exc_info.value.code == 4001

    def test_accepts_valid_token_and_subscribes(self, client: TestClient):
        token = create_access_token(subject="user-1", role="admin")
        with client.websocket_connect(f"/ws/realtime?token={token}") as ws:
            hello = ws.receive_json()
            assert hello["type"] == "subscribed"
            assert hello["org_id"] == "user-1"  # sub fallback for org_id
            assert hello["data"]["user_id"] == "user-1"

    def test_broadcast_reaches_subscriber(self, client: TestClient):
        token = create_access_token(subject="user-1", role="admin")
        with client.websocket_connect(f"/ws/realtime?token={token}") as ws:
            hello = ws.receive_json()
            assert hello["type"] == "subscribed"

            resp = client.post(
                "/_test/publish",
                json={
                    "org_id": "user-1",
                    "event": {"type": "new_situation", "data": {"id": "sit-42"}},
                },
            )
            assert resp.status_code == 200
            assert resp.json()["delivered"] == 1

            event = ws.receive_json()
            assert event["type"] == "new_situation"
            assert event["data"]["id"] == "sit-42"
            assert event["org_id"] == "user-1"

    def test_tenant_isolation_over_endpoint(self, client: TestClient):
        token_a = create_access_token(subject="org-a-user", role="admin")
        token_b = create_access_token(subject="org-b-user", role="admin")
        with (
            client.websocket_connect(f"/ws/realtime?token={token_a}") as ws_a,
            client.websocket_connect(f"/ws/realtime?token={token_b}") as ws_b,
        ):
            ws_a.receive_json()  # subscribed
            ws_b.receive_json()  # subscribed

            resp = client.post(
                "/_test/publish",
                json={
                    "org_id": "org-a-user",
                    "event": {
                        "type": "firewall_event",
                        "data": {"decision": "deny"},
                    },
                },
            )
            assert resp.status_code == 200
            assert resp.json()["delivered"] == 1

            ev = ws_a.receive_json()
            assert ev["type"] == "firewall_event"
            assert ev["org_id"] == "org-a-user"

            # ws_b must not see the event — confirm by sending a broadcast
            # specifically for org-b and ensuring that's the next frame.
            resp2 = client.post(
                "/_test/publish",
                json={
                    "org_id": "org-b-user",
                    "event": {"type": "metric_update", "data": {"cpu": 42}},
                },
            )
            assert resp2.status_code == 200
            next_for_b = ws_b.receive_json()
            assert next_for_b["type"] == "metric_update"
            assert next_for_b["org_id"] == "org-b-user"

    def test_stats_endpoint(self, client: TestClient):
        response = client.get("/ws/realtime/stats")
        assert response.status_code == 200
        body = response.json()
        assert "total_connections" in body
        assert "per_org" in body
        assert "heartbeat_interval_s" in body
