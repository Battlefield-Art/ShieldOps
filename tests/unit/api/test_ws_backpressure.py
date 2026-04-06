"""WebSocket broadcaster back-pressure — TDD tests (#5)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from starlette.websockets import WebSocketState

from shieldops.api.ws.bounded_sender import (
    BoundedSender,
    OverflowPolicy,
    SenderClosed,
)


def _mock_ws() -> MagicMock:
    ws = MagicMock()
    ws.client_state = WebSocketState.CONNECTED
    ws.send_json = AsyncMock()
    ws.close = AsyncMock()
    return ws


class TestBoundedSenderFastConsumer:
    @pytest.mark.asyncio
    async def test_fast_consumer_receives_all_messages(self) -> None:
        ws = _mock_ws()
        sender = BoundedSender(ws, max_pending=10, overflow=OverflowPolicy.DROP_OLDEST)
        await sender.start()
        try:
            for i in range(5):
                await sender.enqueue({"seq": i})
            await sender.flush()
            assert ws.send_json.await_count == 5
        finally:
            await sender.stop()


class TestBoundedSenderSlowConsumer:
    @pytest.mark.asyncio
    async def test_slow_consumer_drops_oldest_when_queue_full(self) -> None:
        """With DROP_OLDEST, older messages are dropped when the queue is saturated."""
        ws = _mock_ws()

        async def _slow_send(data: dict) -> None:
            await asyncio.sleep(0.02)

        ws.send_json = AsyncMock(side_effect=_slow_send)

        sender = BoundedSender(ws, max_pending=3, overflow=OverflowPolicy.DROP_OLDEST)
        await sender.start()
        try:
            # Enqueue 10 messages back-to-back faster than consumer can drain
            for i in range(10):
                await sender.enqueue({"seq": i})
            # Give the drain loop time to finish what's left in the queue
            await asyncio.sleep(0.5)
        finally:
            await sender.stop()

        # Drop counter > 0 proves back-pressure kicked in
        assert sender.dropped_count > 0
        # At least some messages made it through
        assert ws.send_json.await_count >= 1
        # The delivered count cannot exceed 10 (nothing invented)
        assert ws.send_json.await_count <= 10

    @pytest.mark.asyncio
    async def test_other_consumers_unaffected_by_slow_one(self) -> None:
        """A slow consumer must not block a fast one — fan-out stays parallel."""
        fast_ws = _mock_ws()
        slow_ws = _mock_ws()

        async def _slow(data: dict) -> None:
            await asyncio.sleep(0.1)

        slow_ws.send_json = AsyncMock(side_effect=_slow)

        fast_sender = BoundedSender(fast_ws, max_pending=10, overflow=OverflowPolicy.DROP_OLDEST)
        slow_sender = BoundedSender(slow_ws, max_pending=3, overflow=OverflowPolicy.DROP_OLDEST)
        await fast_sender.start()
        await slow_sender.start()
        try:
            # Enqueue 5 to both
            for i in range(5):
                await fast_sender.enqueue({"seq": i})
                await slow_sender.enqueue({"seq": i})
            # Wait briefly — fast consumer should be fully drained
            await asyncio.sleep(0.05)
            # Fast consumer got all 5
            assert fast_ws.send_json.await_count == 5
            # Slow consumer is lagging — still fewer than 5 delivered
            # (may have 0 or 1 depending on timing) — but the fast one isn't blocked
        finally:
            await fast_sender.stop()
            await slow_sender.stop()


class TestBoundedSenderFailOnClosed:
    @pytest.mark.asyncio
    async def test_enqueue_after_stop_raises(self) -> None:
        ws = _mock_ws()
        sender = BoundedSender(ws, max_pending=5, overflow=OverflowPolicy.DROP_OLDEST)
        await sender.start()
        await sender.stop()
        with pytest.raises(SenderClosed):
            await sender.enqueue({"seq": 1})


class TestBoundedSenderDisconnectPolicy:
    @pytest.mark.asyncio
    async def test_disconnect_policy_closes_websocket_on_overflow(self) -> None:
        """With DISCONNECT policy, overflow triggers a close."""
        ws = _mock_ws()

        async def _slow_send(data: dict) -> None:
            await asyncio.sleep(0.05)

        ws.send_json = AsyncMock(side_effect=_slow_send)

        sender = BoundedSender(ws, max_pending=2, overflow=OverflowPolicy.DISCONNECT)
        await sender.start()
        try:
            # Enqueue enough to overflow
            for i in range(10):
                try:
                    await sender.enqueue({"seq": i})
                except SenderClosed:
                    break
        finally:
            await sender.stop()

        # The websocket should have been closed
        ws.close.assert_awaited()
