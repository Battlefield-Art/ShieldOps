"""WebSocket heartbeat reaping — TDD behavioral tests (#7)."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from shieldops.api.ws.broadcaster import (
    HEARTBEAT_TIMEOUT_S,
    Broadcaster,
    _Connection,
)


def _mock_ws() -> MagicMock:
    ws = MagicMock()
    ws.close = AsyncMock()
    ws.send_json = AsyncMock()
    return ws


class TestNoStaleConnections:
    @pytest.mark.asyncio
    async def test_cleanup_returns_zero_when_all_fresh(self) -> None:
        bc = Broadcaster()
        await bc.subscribe("org-a", _mock_ws())
        await bc.subscribe("org-a", _mock_ws())
        reaped = await bc.cleanup_stale()
        assert reaped == 0
        stats = bc.get_stats()
        assert stats["total_connections"] == 2


class TestStaleReaping:
    @pytest.mark.asyncio
    async def test_stale_connection_is_reaped_and_closed(self) -> None:
        bc = Broadcaster()
        ws_stale = _mock_ws()
        ws_fresh = _mock_ws()
        conn_stale = await bc.subscribe("org-a", ws_stale)
        conn_fresh = await bc.subscribe("org-a", ws_fresh)
        assert conn_stale is not None
        assert conn_fresh is not None

        # Make conn_stale stale by backdating its last_pong
        conn_stale.last_pong = time.time() - (HEARTBEAT_TIMEOUT_S + 5)

        reaped = await bc.cleanup_stale()

        assert reaped == 1
        # Stale ws was closed with code 4002
        ws_stale.close.assert_awaited_once()
        args = ws_stale.close.await_args
        assert args.kwargs.get("code") == 4002 or (args.args and args.args[0] == 4002)
        # Fresh ws was NOT closed
        ws_fresh.close.assert_not_called()
        # Registry only has the fresh connection
        stats = bc.get_stats()
        assert stats["total_connections"] == 1

    @pytest.mark.asyncio
    async def test_touch_prevents_reaping(self) -> None:
        bc = Broadcaster()
        ws = _mock_ws()
        conn = await bc.subscribe("org-b", ws)
        assert conn is not None

        # Backdate
        conn.last_pong = time.time() - (HEARTBEAT_TIMEOUT_S + 5)
        # Touch revives it
        bc.touch(conn)

        reaped = await bc.cleanup_stale()
        assert reaped == 0
        ws.close.assert_not_called()

    @pytest.mark.asyncio
    async def test_is_stale_boundary(self) -> None:
        """Exactly-at-timeout should NOT be stale; strictly greater is stale."""
        ws = _mock_ws()
        conn = _Connection(websocket=ws, org_id="org-c")
        now = time.time()
        conn.last_pong = now - HEARTBEAT_TIMEOUT_S  # exactly at boundary
        assert conn.is_stale(now) is False
        conn.last_pong = now - HEARTBEAT_TIMEOUT_S - 0.001
        assert conn.is_stale(now) is True

    @pytest.mark.asyncio
    async def test_reaping_multi_tenant_isolation(self) -> None:
        """Reaping a stale conn in org-a must not touch org-b connections."""
        bc = Broadcaster()
        ws_a = _mock_ws()
        ws_b = _mock_ws()
        conn_a = await bc.subscribe("org-a", ws_a)
        await bc.subscribe("org-b", ws_b)
        assert conn_a is not None

        conn_a.last_pong = time.time() - (HEARTBEAT_TIMEOUT_S + 10)
        reaped = await bc.cleanup_stale()

        assert reaped == 1
        stats = bc.get_stats()
        assert stats["per_org"].get("org-b", 0) == 1
        assert stats["per_org"].get("org-a", 0) == 0


class TestBackgroundCleanupTask:
    @pytest.mark.asyncio
    async def test_start_and_stop_cleanup_task(self) -> None:
        bc = Broadcaster()
        await bc.start_cleanup_task()
        assert bc._cleanup_task is not None
        assert not bc._cleanup_task.done()
        # Idempotent: calling start again does nothing
        task_ref = bc._cleanup_task
        await bc.start_cleanup_task()
        assert bc._cleanup_task is task_ref
        # Stop
        await bc.stop_cleanup_task()
        assert bc._cleanup_task is None

    @pytest.mark.asyncio
    async def test_stop_when_never_started_is_safe(self) -> None:
        bc = Broadcaster()
        # Should not raise even if no task was started
        await bc.stop_cleanup_task()
        assert bc._cleanup_task is None
