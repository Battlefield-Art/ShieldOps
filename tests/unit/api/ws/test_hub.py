"""Contract tests for the WebSocket Hub core — RFC #242 PR-1.

The central test in this file is
:meth:`TestReplayContract.test_publish_disconnect_reconnect_with_since_id_delivers_exactly_missed_events`
— the single test we could not write before RFC #242 existed. Its purpose
is to lock the "replay is enforced" invariant: calling :meth:`Hub.publish`
always writes to the buffer before fanning out, and a reconnecting client
with ``since_id`` receives exactly the events it missed, in order, with no
gaps and no duplicates.

The other tests lock the other structural invariants:

- **Backpressure is on by default** — a flooded queue applies the drop
  policy without stalling the publish path.
- **Attach is atomic** — events published between "replay" and "live
  forwarding" land in the subscription queue in order, with no gaps.
- **Tenant isolation** — two channels don't cross-pollinate.
- **Auth failure closes with 4001** — the canonical auth failure code.

All tests use in-memory adapters — no FastAPI, no real WebSocket, no real
time, no mocks. Each test runs in <10 ms.
"""

from __future__ import annotations

import asyncio

import pytest

from shieldops.api.ws.adapters import (
    InMemoryBuffer,
    InMemoryTransport,
    ManualClock,
    NullLogger,
    NullTracer,
    StaticTokenAuthenticator,
)
from shieldops.api.ws.core import AuthError, Event, Hub, HubConfig, Principal

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_hub(
    *,
    tokens: dict[str, Principal] | None = None,
    queue_max: int = 256,
    drop_policy: str = "oldest",
) -> tuple[Hub, InMemoryTransport]:
    """Build a hub with all in-memory adapters + return the transport
    for test inspection."""
    transport = InMemoryTransport()
    hub = Hub(
        transport=transport,
        buffer=InMemoryBuffer(max_per_channel=100),
        auth=StaticTokenAuthenticator(tokens or {"t1": Principal(tenant_id="org-a", user_id="u1")}),
        clock=ManualClock(start=1_000.0),
        log=NullLogger(),
        tracer=NullTracer(),
        config=HubConfig(queue_max=queue_max, drop_policy=drop_policy),  # type: ignore[arg-type]
    )
    return hub, transport


async def _drain(hub: Hub, *, iterations: int = 100) -> None:
    """Yield control enough times for all pending queue items to drain."""
    for _ in range(iterations):
        pending = any(not sub.queue.empty() for sub in hub._subscriptions.values())
        if not pending:
            return
        await asyncio.sleep(0)


# ---------------------------------------------------------------------------
# 1. THE CONTRACT TEST — replay-on-reconnect with since_id
# ---------------------------------------------------------------------------


class TestReplayContract:
    """The central test this RFC exists to make possible."""

    @pytest.mark.asyncio
    async def test_publish_disconnect_reconnect_with_since_id_delivers_exactly_missed_events(
        self,
    ) -> None:
        """publish 5 → detach → advance clock → reconnect with since_id=first
        → receive exactly events 2..5. No duplicates. No gaps."""
        hub, transport = _make_hub()

        # First connection receives all 5 events live.
        transport.register("c1")
        await hub.attach(conn_id="c1", channel="investigation:i1", token="t1")

        ids: list[str] = []
        for i in range(5):
            eid = await hub.publish("investigation:i1", Event(kind="step", data={"n": i}))
            ids.append(eid)

        await _drain(hub)
        assert len(transport.sent("c1")) == 5
        assert [s["id"] for s in transport.sent("c1")] == ids

        # Disconnect, advance time.
        await hub.detach("c1")
        hub.clock.advance(2.0)  # type: ignore[attr-defined]

        # Reconnect as c2 with since_id pointing at the FIRST event.
        # We should get events 2..5 (ids[1:]) and nothing else.
        transport.register("c2")
        await hub.attach(
            conn_id="c2",
            channel="investigation:i1",
            token="t1",
            since_id=ids[0],
        )

        await _drain(hub)

        replayed = transport.sent("c2")
        replayed_ids = [r["id"] for r in replayed]
        assert replayed_ids == ids[1:], (
            f"expected exactly missed events {ids[1:]}, got {replayed_ids}"
        )
        # No duplicates
        assert len(set(replayed_ids)) == len(replayed_ids)


# ---------------------------------------------------------------------------
# 2. Attach is atomic w.r.t. concurrent publish
# ---------------------------------------------------------------------------


class TestAttachAtomicity:
    @pytest.mark.asyncio
    async def test_replay_and_live_events_arrive_in_order_with_no_gap(self) -> None:
        """Pre-publish 3 events. Reconnect with since_id of event 1. Then
        publish a 4th event. Assert c2 sees events 2, 3, 4 in order."""
        hub, transport = _make_hub()

        # Seed the buffer with 3 events (no subscriber).
        ids: list[str] = []
        for i in range(3):
            eid = await hub.publish("ch", Event(kind="step", data={"n": i}))
            ids.append(eid)

        # Attach c2 with since_id=ids[0] → queue should be seeded with
        # ids[1] and ids[2] from replay.
        transport.register("c2")
        await hub.attach(conn_id="c2", channel="ch", token="t1", since_id=ids[0])

        # Publish a 4th event AFTER attach. Because publish takes the
        # same lock, it runs strictly after the attach's replay +
        # register, so its enqueue lands after the replayed events.
        eid4 = await hub.publish("ch", Event(kind="step", data={"n": 99}))

        await _drain(hub)

        sent = transport.sent("c2")
        sent_ids = [s["id"] for s in sent]
        assert sent_ids == [ids[1], ids[2], eid4]

    @pytest.mark.asyncio
    async def test_attach_without_since_id_gets_no_replay(self) -> None:
        """A fresh client that doesn't pass since_id sees only live events."""
        hub, transport = _make_hub()

        # Pre-seed buffer.
        for i in range(3):
            await hub.publish("ch", Event(kind="step", data={"n": i}))

        transport.register("c1")
        await hub.attach(conn_id="c1", channel="ch", token="t1")

        eid = await hub.publish("ch", Event(kind="step", data={"n": 99}))
        await _drain(hub)

        sent = transport.sent("c1")
        assert len(sent) == 1
        assert sent[0]["id"] == eid

    @pytest.mark.asyncio
    async def test_evicted_since_id_falls_back_to_full_window(self) -> None:
        """If since_id is older than the buffer's oldest retained event,
        the client receives the entire current window (self-recovery)."""
        hub, transport = _make_hub()
        # Force a tiny buffer.
        hub.buffer = InMemoryBuffer(max_per_channel=3)  # type: ignore[assignment]

        # Publish 5 events → buffer now holds events 3, 4, 5. Event 1 is evicted.
        ids: list[str] = []
        for i in range(5):
            eid = await hub.publish("ch", Event(kind="step", data={"n": i}))
            ids.append(eid)

        # Attach with since_id=ids[0] which has been evicted.
        transport.register("c2")
        await hub.attach(conn_id="c2", channel="ch", token="t1", since_id=ids[0])
        await _drain(hub)

        sent_ids = [s["id"] for s in transport.sent("c2")]
        # Full current window — events 3, 4, 5.
        assert sent_ids == ids[2:]


# ---------------------------------------------------------------------------
# 3. Channel isolation
# ---------------------------------------------------------------------------


class TestChannelIsolation:
    @pytest.mark.asyncio
    async def test_publish_to_one_channel_does_not_reach_another(self) -> None:
        hub, transport = _make_hub()

        transport.register("c_a")
        transport.register("c_b")
        await hub.attach(conn_id="c_a", channel="ch_a", token="t1")
        await hub.attach(conn_id="c_b", channel="ch_b", token="t1")

        await hub.publish("ch_a", Event(kind="e", data={"who": "a"}))
        await hub.publish("ch_b", Event(kind="e", data={"who": "b"}))
        await _drain(hub)

        sent_a = transport.sent("c_a")
        sent_b = transport.sent("c_b")
        assert len(sent_a) == 1 and sent_a[0]["data"] == {"who": "a"}
        assert len(sent_b) == 1 and sent_b[0]["data"] == {"who": "b"}

    @pytest.mark.asyncio
    async def test_publish_fans_out_to_all_subscribers_in_a_channel(
        self,
    ) -> None:
        hub, transport = _make_hub()

        transport.register("c1")
        transport.register("c2")
        transport.register("c3")
        await hub.attach(conn_id="c1", channel="ch", token="t1")
        await hub.attach(conn_id="c2", channel="ch", token="t1")
        await hub.attach(conn_id="c3", channel="ch", token="t1")

        await hub.publish("ch", Event(kind="e", data={"n": 1}))
        await _drain(hub)

        for conn in ("c1", "c2", "c3"):
            sent = transport.sent(conn)
            assert len(sent) == 1 and sent[0]["data"] == {"n": 1}


# ---------------------------------------------------------------------------
# 4. Auth failure
# ---------------------------------------------------------------------------


class TestAuth:
    @pytest.mark.asyncio
    async def test_auth_failure_raises_auth_error_and_closes_4001(self) -> None:
        hub, transport = _make_hub()
        transport.register("c1")

        with pytest.raises(AuthError):
            await hub.attach(conn_id="c1", channel="ch", token="bogus-token")

        assert transport.close_code("c1") == 4001
        assert not transport.is_open("c1")

    @pytest.mark.asyncio
    async def test_principal_is_threaded_through_subscription(self) -> None:
        hub, transport = _make_hub(
            tokens={
                "t1": Principal(tenant_id="org-a", user_id="u1"),
            }
        )
        transport.register("c1")
        sub = await hub.attach(conn_id="c1", channel="ch", token="t1")
        assert sub.principal.tenant_id == "org-a"
        assert sub.principal.user_id == "u1"


# ---------------------------------------------------------------------------
# 5. Detach and lifecycle
# ---------------------------------------------------------------------------


class TestDetach:
    @pytest.mark.asyncio
    async def test_detach_removes_subscription_and_closes_transport(
        self,
    ) -> None:
        hub, transport = _make_hub()
        transport.register("c1")
        await hub.attach(conn_id="c1", channel="ch", token="t1")

        assert hub.active_connections() == 1
        assert hub.subscriber_count("ch") == 1

        await hub.detach("c1")

        assert hub.active_connections() == 0
        assert hub.subscriber_count("ch") == 0
        assert not transport.is_open("c1")

    @pytest.mark.asyncio
    async def test_detach_unknown_conn_id_is_noop(self) -> None:
        hub, _ = _make_hub()
        # Should not raise.
        await hub.detach("never-existed")

    @pytest.mark.asyncio
    async def test_publish_after_detach_does_not_reach_connection(self) -> None:
        hub, transport = _make_hub()
        transport.register("c1")
        await hub.attach(conn_id="c1", channel="ch", token="t1")
        await hub.detach("c1")

        # Publishing to the channel with no subscribers must not send.
        await hub.publish("ch", Event(kind="e", data={}))
        await _drain(hub)

        assert transport.sent("c1") == []


# ---------------------------------------------------------------------------
# 6. Backpressure
# ---------------------------------------------------------------------------


class TestBackpressure:
    @pytest.mark.asyncio
    async def test_queue_full_with_drop_oldest_keeps_newest_events(self) -> None:
        """With queue_max=3 and drop_oldest, flooding 5 events before the
        drain task can run keeps only the 3 newest."""
        # A blocking transport — refuses to send until released — lets us
        # flood the queue without the drain task emptying it.
        flood_gate = asyncio.Event()

        class BlockingTransport(InMemoryTransport):
            async def send(self, conn_id: str, payload: bytes) -> None:
                await flood_gate.wait()
                await super().send(conn_id, payload)

        transport = BlockingTransport()
        hub = Hub(
            transport=transport,
            buffer=InMemoryBuffer(),
            auth=StaticTokenAuthenticator({"t1": Principal(tenant_id="org-a")}),
            clock=ManualClock(),
            log=NullLogger(),
            tracer=NullTracer(),
            config=HubConfig(queue_max=3, drop_policy="oldest"),  # type: ignore[arg-type]
        )

        transport.register("c1")
        await hub.attach(conn_id="c1", channel="ch", token="t1")

        # Flood 5 events while the drain task is blocked.
        ids: list[str] = []
        for i in range(5):
            eid = await hub.publish("ch", Event(kind="e", data={"n": i}))
            ids.append(eid)

        # Now release the drain task.
        flood_gate.set()
        await _drain(hub)

        sent_ids = [s["id"] for s in transport.sent("c1")]
        # drop_oldest → we keep the newest 3 events.
        assert len(sent_ids) == 3
        assert sent_ids == ids[2:]


# ---------------------------------------------------------------------------
# 7. Publish contract: buffer-before-fanout is unbypassable
# ---------------------------------------------------------------------------


class TestStructuralInvariants:
    @pytest.mark.asyncio
    async def test_publish_always_appends_to_buffer_even_with_no_subscribers(
        self,
    ) -> None:
        """The whole replay-on-reconnect feature depends on this."""
        hub, _ = _make_hub()

        # No subscribers — still should persist.
        await hub.publish("ch", Event(kind="e", data={"n": 1}))
        await hub.publish("ch", Event(kind="e", data={"n": 2}))

        # Now attach with since_id=None → should see both events (full window).
        transport = hub.transport
        transport.register("c1")  # type: ignore[attr-defined]
        await hub.attach(conn_id="c1", channel="ch", token="t1", since_id="evt-000000000")
        await _drain(hub)

        sent = transport.sent("c1")  # type: ignore[attr-defined]
        assert len(sent) == 2
        assert sent[0]["data"] == {"n": 1}
        assert sent[1]["data"] == {"n": 2}

    @pytest.mark.asyncio
    async def test_event_ids_are_monotonic_per_hub(self) -> None:
        hub, _ = _make_hub()
        ids = []
        for _ in range(10):
            ids.append(await hub.publish("ch", Event(kind="e", data={})))
        # Lexicographically monotonic because they're zero-padded.
        assert ids == sorted(ids)
        assert len(set(ids)) == 10
