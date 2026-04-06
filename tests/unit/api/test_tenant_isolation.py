"""Cross-tenant isolation audit — TDD tests (#6).

Verifies that endpoints scoped to an organization cannot leak data to a
different organization. Uses a helper that injects a mock user for Org A,
creates data, then swaps to Org B and asserts no visibility.
"""

from __future__ import annotations

from collections.abc import Callable
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.auth.dependencies import get_current_user


def _user_factory(org_id: str, user_id: str = "u") -> Callable[[], MagicMock]:
    async def _user() -> MagicMock:
        u = MagicMock()
        u.org_id = org_id
        u.id = user_id
        return u

    return _user


class TestFirewallDashboardIsolation:
    """Firewall dashboard stats + stream must not leak across orgs."""

    def test_stats_isolation(self) -> None:
        from shieldops.api.routes import firewall_dashboard

        firewall_dashboard.reset_counters()
        app = FastAPI()
        app.include_router(firewall_dashboard.router)

        # Record evaluations
        firewall_dashboard.record_evaluation(
            org_id="org-a", tool_name="read_logs", decision="allow", risk_score=0.2
        )
        firewall_dashboard.record_evaluation(
            org_id="org-a", tool_name="delete_db", decision="deny", risk_score=0.95
        )
        firewall_dashboard.record_evaluation(
            org_id="org-b", tool_name="list_users", decision="allow", risk_score=0.1
        )

        app.dependency_overrides[get_current_user] = _user_factory("org-a")
        with TestClient(app) as client:
            stats_a = client.get("/firewall/dashboard/stats").json()
        assert stats_a["total_evaluations"] == 2

        app.dependency_overrides[get_current_user] = _user_factory("org-b")
        with TestClient(app) as client:
            stats_b = client.get("/firewall/dashboard/stats").json()
        assert stats_b["total_evaluations"] == 1

    def test_stream_isolation(self) -> None:
        from shieldops.api.routes import firewall_dashboard

        firewall_dashboard.reset_counters()
        app = FastAPI()
        app.include_router(firewall_dashboard.router)

        for _ in range(3):
            firewall_dashboard.record_evaluation(
                org_id="org-a", tool_name="t", decision="allow", risk_score=0.1
            )
        firewall_dashboard.record_evaluation(
            org_id="org-b", tool_name="t", decision="allow", risk_score=0.1
        )

        app.dependency_overrides[get_current_user] = _user_factory("org-a")
        with TestClient(app) as client:
            a_stream = client.get("/firewall/dashboard/stream").json()

        app.dependency_overrides[get_current_user] = _user_factory("org-b")
        with TestClient(app) as client:
            b_stream = client.get("/firewall/dashboard/stream").json()

        assert a_stream["total"] == 3
        assert b_stream["total"] == 1


class TestOnboardingIsolation:
    """Onboarding progress must be per-org."""

    def test_progress_isolation(self) -> None:
        from shieldops.api.routes import onboarding_progress

        onboarding_progress.reset_progress()
        app = FastAPI()
        app.include_router(onboarding_progress.router)

        app.dependency_overrides[get_current_user] = _user_factory("org-a")
        with TestClient(app) as client:
            client.post("/onboarding/progress", json={"step": "signup"})
            client.post("/onboarding/progress", json={"step": "email_verified"})

        app.dependency_overrides[get_current_user] = _user_factory("org-b")
        with TestClient(app) as client:
            prog = client.get("/onboarding/progress").json()

        # Org B should see no completed steps
        assert prog["percent_complete"] == 0.0
        assert all(not s["completed"] for s in prog["steps"])


class TestRateLimiterIsolation:
    """Token bucket keys must not bleed across orgs."""

    @pytest.mark.asyncio
    async def test_rate_limits_are_per_key(self) -> None:
        from shieldops.api.middleware.token_bucket import TokenBucket

        bucket = TokenBucket(capacity=3, refill_rate_per_sec=1.0)
        # Drain org-a
        for _ in range(3):
            await bucket.try_consume("org-a")
        # Org-a blocked
        assert (await bucket.try_consume("org-a"))[0] is False
        # Org-b unaffected
        for _ in range(3):
            assert (await bucket.try_consume("org-b"))[0] is True


class TestWebSocketBroadcastIsolation:
    """Broadcaster events must not cross orgs."""

    @pytest.mark.asyncio
    async def test_broadcast_to_org_does_not_reach_others(self) -> None:
        from unittest.mock import AsyncMock

        from starlette.websockets import WebSocketState

        from shieldops.api.ws.broadcaster import Broadcaster

        bc = Broadcaster()

        def _mock_ws() -> MagicMock:
            ws = MagicMock()
            ws.client_state = WebSocketState.CONNECTED
            ws.close = AsyncMock()
            ws.send_json = AsyncMock()
            return ws

        ws_a = _mock_ws()
        ws_b = _mock_ws()
        await bc.subscribe("org-a", ws_a)
        await bc.subscribe("org-b", ws_b)

        await bc.broadcast_to_org("org-a", "test_event", {"foo": "bar"})

        # ws_a got the event, ws_b did NOT
        assert ws_a.send_json.await_count == 1
        ws_b.send_json.assert_not_called()
