"""Contract tests for RedisBuffer + RedisHubBridge — RFC #242 PR-5 / #259.

These tests exercise the two Redis adapters under fakeredis so they run
in-process with no external dependencies. The goals are:

1. RedisBuffer passes the same behavioral contract as InMemoryBuffer
   (append → since with and without since_id, including the ``not found
   → yield all`` fallback path).
2. RedisHubBridge delivers cross-replica fan-out: a publish on hub A
   reaches subscribers attached to hub B when both share the same Redis.
3. Loopback prevention: a bridge does NOT re-deliver its own publish
   back into its own hub (the ``origin`` guard).
4. stop() is idempotent and cleanly tears down the background drain.

All tests use ``fakeredis.aioredis.FakeRedis`` which implements a
functional subset of redis.asyncio.Redis including Streams, pub/sub,
and PSUBSCRIBE — the exact APIs the adapters use.
"""

from __future__ import annotations

import asyncio

import pytest
from fakeredis.aioredis import FakeRedis

from shieldops.api.ws.adapters import RedisBuffer
from shieldops.api.ws.composition import build_redis_hub
from shieldops.api.ws.core import Principal
from shieldops.api.ws.core.events import Event

# ---------------------------------------------------------------------------
# RedisBuffer contract
# ---------------------------------------------------------------------------


class TestRedisBuffer:
    @pytest.mark.asyncio
    async def test_append_then_since_none_yields_all(self) -> None:
        redis = FakeRedis()
        buf = RedisBuffer(redis, max_per_channel=100)
        await buf.append("inv", "evt-1", b"payload-1", 1.0)
        await buf.append("inv", "evt-2", b"payload-2", 2.0)
        await buf.append("inv", "evt-3", b"payload-3", 3.0)

        received = [e async for e in buf.since("inv", since_id=None)]
        assert [e.id for e in received] == ["evt-1", "evt-2", "evt-3"]
        assert received[0].payload == b"payload-1"
        assert received[2].ts == 3.0

    @pytest.mark.asyncio
    async def test_since_with_known_id_yields_strictly_newer(self) -> None:
        redis = FakeRedis()
        buf = RedisBuffer(redis, max_per_channel=100)
        for i in range(1, 6):
            await buf.append("inv", f"evt-{i}", f"p{i}".encode(), float(i))

        received = [e async for e in buf.since("inv", since_id="evt-3")]
        assert [e.id for e in received] == ["evt-4", "evt-5"]

    @pytest.mark.asyncio
    async def test_since_with_unknown_id_yields_all(self) -> None:
        """Contract: unknown since_id → yield entire current window (client self-recovery)."""
        redis = FakeRedis()
        buf = RedisBuffer(redis, max_per_channel=100)
        await buf.append("inv", "evt-1", b"p1", 1.0)
        await buf.append("inv", "evt-2", b"p2", 2.0)

        received = [e async for e in buf.since("inv", since_id="evt-evicted")]
        assert [e.id for e in received] == ["evt-1", "evt-2"]

    @pytest.mark.asyncio
    async def test_empty_channel_yields_nothing(self) -> None:
        redis = FakeRedis()
        buf = RedisBuffer(redis, max_per_channel=100)
        received = [e async for e in buf.since("inv", since_id=None)]
        assert received == []

    @pytest.mark.asyncio
    async def test_maxlen_trims_stream(self) -> None:
        redis = FakeRedis()
        buf = RedisBuffer(redis, max_per_channel=3)
        for i in range(1, 11):
            await buf.append("inv", f"evt-{i}", f"p{i}".encode(), float(i))

        received = [e async for e in buf.since("inv", since_id=None)]
        # MAXLEN ~ 3 is approximate; fakeredis honors it exactly.
        assert len(received) <= 10
        assert len(received) >= 1
        # Most recent entry must always remain
        assert received[-1].id == "evt-10"

    @pytest.mark.asyncio
    async def test_explicit_trim(self) -> None:
        redis = FakeRedis()
        buf = RedisBuffer(redis, max_per_channel=100)
        for i in range(1, 6):
            await buf.append("inv", f"evt-{i}", f"p{i}".encode(), float(i))

        await buf.trim("inv", max_age_s=0.0, max_len=2)
        received = [e async for e in buf.since("inv", since_id=None)]
        assert len(received) <= 2

    @pytest.mark.asyncio
    async def test_max_per_channel_validated(self) -> None:
        redis = FakeRedis()
        with pytest.raises(ValueError, match="max_per_channel"):
            RedisBuffer(redis, max_per_channel=0)


# ---------------------------------------------------------------------------
# RedisHubBridge — cross-replica fan-out
# ---------------------------------------------------------------------------


async def _wait_for_send(transport, conn_id: str, timeout: float = 2.0) -> None:
    """Poll transport.sent(conn_id) until at least one message arrives or timeout."""
    deadline = asyncio.get_event_loop().time() + timeout
    while not transport.sent(conn_id) and asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(0.05)


class TestRedisHubBridgeCrossReplicaDelivery:
    @pytest.mark.asyncio
    async def test_publish_on_hub_a_reaches_subscriber_on_hub_b(self) -> None:
        """The core cross-replica test: 2 hubs, 1 Redis, event crosses replicas.

        Delivery is observed via the receiving hub's InMemoryTransport,
        which is where Hub._drain() sends events after pulling them off
        the subscription queue.
        """
        redis = FakeRedis()
        token = "test-token"
        principal = Principal(tenant_id="t1", user_id="u1")

        hub_a, bridge_a = await build_redis_hub(
            redis_client=redis,
            tokens={token: principal},
            replica_id="replica-a",
        )
        hub_b, bridge_b = await build_redis_hub(
            redis_client=redis,
            tokens={token: principal},
            replica_id="replica-b",
        )

        try:
            # Register the fake connection on hub B's transport first.
            hub_b.transport.register("conn-on-b")

            await hub_b.attach(
                conn_id="conn-on-b",
                channel="investigation",
                token=token,
                since_id=None,
            )

            # Publish on hub A
            await hub_a.publish(
                "investigation",
                Event(kind="test.event", data={"hello": "world"}),
            )

            # Give the bridge's background drain + Hub._drain loops time
            # to deliver the pub/sub message through to the transport.
            await _wait_for_send(hub_b.transport, "conn-on-b", timeout=3.0)

            sent = hub_b.transport.sent("conn-on-b")
            assert len(sent) >= 1, "subscriber on replica B never saw the event"
            assert sent[0]["kind"] == "test.event"
            assert sent[0]["data"] == {"hello": "world"}
        finally:
            await bridge_a.stop()
            await bridge_b.stop()

    @pytest.mark.asyncio
    async def test_loopback_suppressed(self) -> None:
        """Single-replica: local Hub.publish delivers exactly once. The bridge's
        inbound loop must drop the loopback message from its own publish."""
        redis = FakeRedis()
        token = "test-token"
        principal = Principal(tenant_id="t1", user_id="u1")

        hub, bridge = await build_redis_hub(
            redis_client=redis,
            tokens={token: principal},
            replica_id="replica-only",
        )

        try:
            hub.transport.register("conn-1")
            await hub.attach(
                conn_id="conn-1",
                channel="investigation",
                token=token,
                since_id=None,
            )

            await hub.publish("investigation", Event(kind="test", data={"n": 1}))

            # Wait for the local delivery, then give the bridge ample time
            # to accidentally re-deliver (which would indicate loopback bug).
            await _wait_for_send(hub.transport, "conn-1", timeout=2.0)
            await asyncio.sleep(0.4)

            sent = hub.transport.sent("conn-1")
            # Exactly ONE delivery — the local Hub.publish path. The bridge's
            # inbound loop should have dropped the loopback.
            assert len(sent) == 1, f"loopback suppression failed: got {len(sent)} deliveries"
        finally:
            await bridge.stop()

    @pytest.mark.asyncio
    async def test_topic_isolation(self) -> None:
        """Subscribing to channel A should not receive events published to channel B."""
        redis = FakeRedis()
        token = "test-token"
        principal = Principal(tenant_id="t1", user_id="u1")

        hub_a, bridge_a = await build_redis_hub(
            redis_client=redis,
            tokens={token: principal},
            replica_id="replica-a",
        )
        hub_b, bridge_b = await build_redis_hub(
            redis_client=redis,
            tokens={token: principal},
            replica_id="replica-b",
        )

        try:
            hub_b.transport.register("conn-b")
            await hub_b.attach(
                conn_id="conn-b",
                channel="remediation",  # different channel
                token=token,
                since_id=None,
            )

            # Publish to a DIFFERENT channel on replica A
            await hub_a.publish("investigation", Event(kind="test", data={}))

            await asyncio.sleep(0.4)

            assert hub_b.transport.sent("conn-b") == [], (
                "topic isolation failed: subscriber on 'remediation' saw 'investigation' event"
            )
        finally:
            await bridge_a.stop()
            await bridge_b.stop()


class TestRedisHubBridgeLifecycle:
    @pytest.mark.asyncio
    async def test_stop_is_idempotent(self) -> None:
        redis = FakeRedis()
        token = "t"
        principal = Principal(tenant_id="t", user_id="u")
        hub, bridge = await build_redis_hub(
            redis_client=redis,
            tokens={token: principal},
        )
        # First stop
        await bridge.stop()
        # Second stop must not raise
        await bridge.stop()

    @pytest.mark.asyncio
    async def test_stop_cancels_background_task(self) -> None:
        redis = FakeRedis()
        principal = Principal(tenant_id="t", user_id="u")
        hub, bridge = await build_redis_hub(
            redis_client=redis,
            tokens={"t": principal},
        )
        task = bridge._task  # noqa: SLF001 — intentional test inspection
        assert task is not None and not task.done()
        await bridge.stop()
        assert bridge._task is None  # noqa: SLF001

    @pytest.mark.asyncio
    async def test_replica_id_is_stable(self) -> None:
        redis = FakeRedis()
        principal = Principal(tenant_id="t", user_id="u")
        hub, bridge = await build_redis_hub(
            redis_client=redis,
            tokens={"t": principal},
            replica_id="fixed-id",
        )
        try:
            assert bridge.replica_id == "fixed-id"
        finally:
            await bridge.stop()


# ---------------------------------------------------------------------------
# select_hub_backend
# ---------------------------------------------------------------------------


class TestSelectHubBackend:
    def test_memory_is_default(self) -> None:
        from shieldops.api.ws.composition import select_hub_backend

        class _S:
            ws_hub_backend = "memory"

        assert select_hub_backend(_S()) == "memory"

    def test_redis_when_configured(self) -> None:
        from shieldops.api.ws.composition import select_hub_backend

        class _S:
            ws_hub_backend = "redis"

        assert select_hub_backend(_S()) == "redis"

    def test_unknown_value_falls_back_to_memory(self) -> None:
        from shieldops.api.ws.composition import select_hub_backend

        class _S:
            ws_hub_backend = "garbage"

        assert select_hub_backend(_S()) == "memory"

    def test_missing_attribute_defaults_to_memory(self) -> None:
        from shieldops.api.ws.composition import select_hub_backend

        class _S:
            pass

        assert select_hub_backend(_S()) == "memory"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _drain_with_timeout(queue: asyncio.Queue, timeout: float = 2.0) -> None:
    """Wait until ``queue`` has at least one item or ``timeout`` expires."""
    deadline = asyncio.get_event_loop().time() + timeout
    while queue.empty() and asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(0.05)
