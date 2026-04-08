"""Integration test — full publish → subscribe → replay path through the
WebSocket Hub via the producer-side :class:`HubBroadcaster` shim.

RFC #242 PR-3 (#257) acceptance criterion #3: an integration test must
cover the full publish → subscribe → replay flow against the Hub that
PR-1 / PR-2 shipped.

This test exercises the Hub the same way the post-migration runners
exercise it in production: callers reach the Hub via
:class:`HubBroadcaster` (which adapts the legacy ``broadcast(channel,
event)`` shape onto :meth:`Hub.publish`); subscribers attach via the
in-memory transport from PR-1 and inspect ``transport.sent(...)``.
"""

from __future__ import annotations

import pytest

from shieldops.api.ws.adapters import (
    InMemoryBuffer,
    InMemoryTransport,
    ManualClock,
    NullLogger,
    NullTracer,
    StaticTokenAuthenticator,
)
from shieldops.api.ws.composition import (
    build_in_memory_hub,
    get_ws_hub,
    set_ws_hub,
    use_test_ws_hub,
)
from shieldops.api.ws.core import Event, Hub, HubConfig, Principal
from shieldops.api.ws.hub_broadcaster import HubBroadcaster


@pytest.fixture(autouse=True)
def _isolate_hub():
    set_ws_hub(None)
    yield
    set_ws_hub(None)


def _build_hub_with_transport(transport: InMemoryTransport) -> Hub:
    """Build a hub wired to a caller-supplied transport.

    ``build_in_memory_hub`` constructs its own ``InMemoryTransport``;
    for these tests we need to inspect the transport directly so the
    fixture builds the hub by hand from the same adapters.
    """
    return Hub(
        transport=transport,
        buffer=InMemoryBuffer(),
        auth=StaticTokenAuthenticator(
            tokens={
                "tok-a": Principal(tenant_id="org-a", user_id="user-a"),
                "tok-b": Principal(tenant_id="org-a", user_id="user-b"),
            }
        ),
        clock=ManualClock(start=0.0),
        log=NullLogger(),
        tracer=NullTracer(),
        config=HubConfig(queue_max=64, replay_max_events=100),
    )


class TestPublishSubscribeReplayPath:
    """End-to-end: producer publishes via HubBroadcaster, subscriber sees it,
    reconnect replays."""

    @pytest.mark.asyncio
    async def test_publish_via_broadcaster_reaches_attached_subscriber(self) -> None:
        transport = InMemoryTransport()
        hub = _build_hub_with_transport(transport)
        set_ws_hub(hub)

        # Subscriber A attaches first.
        transport.register("client-a")
        await hub.attach(
            conn_id="client-a",
            channel="investigation",
            token="tok-a",
            since_id=None,
        )

        # Producer (e.g. an agent runner) reaches the hub via the
        # HubBroadcaster shim using the legacy positional shape.
        broadcaster = HubBroadcaster(get_ws_hub())
        await broadcaster.broadcast(
            "investigation",
            {
                "type": "investigation_update",
                "investigation_id": "inv-1",
                "status": "running",
            },
        )

        # Drain task is async; give it a tick to forward.
        import asyncio

        await asyncio.sleep(0)
        await asyncio.sleep(0)

        sent = transport.sent("client-a")
        assert len(sent) == 1
        envelope = sent[0]
        assert envelope["kind"] == "investigation_update"
        assert envelope["data"]["investigation_id"] == "inv-1"
        assert envelope["data"]["status"] == "running"

        await hub.detach("client-a")

    @pytest.mark.asyncio
    async def test_kwarg_message_shape_is_supported(self) -> None:
        """The vulnerability/lifecycle.py call site uses ``channel=``,
        ``message=`` kwargs — the broadcaster must accept that shape too."""
        transport = InMemoryTransport()
        hub = _build_hub_with_transport(transport)
        set_ws_hub(hub)

        transport.register("client-vuln")
        await hub.attach(
            conn_id="client-vuln",
            channel="vulnerabilities",
            token="tok-a",
            since_id=None,
        )

        broadcaster = HubBroadcaster(hub)
        await broadcaster.broadcast(
            channel="vulnerabilities",
            message={
                "type": "vulnerability_status_changed",
                "vulnerability_id": "CVE-2026-0001",
                "from_status": "open",
                "to_status": "remediated",
            },
        )

        import asyncio

        await asyncio.sleep(0)
        await asyncio.sleep(0)

        sent = transport.sent("client-vuln")
        assert len(sent) == 1
        assert sent[0]["kind"] == "vulnerability_status_changed"
        assert sent[0]["data"]["vulnerability_id"] == "CVE-2026-0001"

        await hub.detach("client-vuln")

    @pytest.mark.asyncio
    async def test_reconnect_replays_missed_events(self) -> None:
        """Client A subscribes, receives events, disconnects, then a new
        connection asking ``since_id=<earlier>`` gets the missed events."""
        transport = InMemoryTransport()
        hub = _build_hub_with_transport(transport)
        set_ws_hub(hub)

        broadcaster = HubBroadcaster(hub)

        # First session — subscribe and receive event #1.
        transport.register("client-a-v1")
        await hub.attach(
            conn_id="client-a-v1",
            channel="investigation",
            token="tok-a",
            since_id=None,
        )

        first_id = await hub.publish(
            "investigation",
            Event(kind="investigation_update", data={"seq": 1}),
        )

        import asyncio

        await asyncio.sleep(0)
        await asyncio.sleep(0)

        first_session = transport.sent("client-a-v1")
        assert len(first_session) == 1
        assert first_session[0]["data"]["seq"] == 1

        # Disconnect.
        await hub.detach("client-a-v1")

        # While disconnected, two more events fly by.
        await broadcaster.broadcast(
            "investigation",
            {"type": "investigation_update", "seq": 2},
        )
        await broadcaster.broadcast(
            "investigation",
            {"type": "investigation_update", "seq": 3},
        )

        # Reconnect with the last-seen id — replay should deliver #2 + #3.
        transport.register("client-a-v2")
        await hub.attach(
            conn_id="client-a-v2",
            channel="investigation",
            token="tok-a",
            since_id=first_id,
        )

        await asyncio.sleep(0)
        await asyncio.sleep(0)

        replayed = transport.sent("client-a-v2")
        seqs = [e["data"]["seq"] for e in replayed]
        # Replay must contain #2 and #3 (in order, no duplicate of #1).
        assert seqs == [2, 3]

        await hub.detach("client-a-v2")

    @pytest.mark.asyncio
    async def test_use_test_ws_hub_round_trip(self) -> None:
        """``use_test_ws_hub()`` swaps the global hub for a block — the
        broadcaster routed via ``get_ws_hub()`` should see the swapped hub."""
        with use_test_ws_hub(build_in_memory_hub(tokens={"t": Principal(tenant_id="t")})):
            broadcaster = HubBroadcaster(get_ws_hub())
            event_id = await broadcaster.broadcast("ch", {"type": "ping", "n": 1})
            assert event_id.startswith("evt-")
        # After exiting the context the hub is cleared.
        with pytest.raises(RuntimeError):
            get_ws_hub()
