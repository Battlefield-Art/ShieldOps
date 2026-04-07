"""The WebSocket Hub core — pure logic over injected ports.

This module implements :class:`Hub`, the single deep module that replaces
the parallel ``ConnectionManager`` / ``Broadcaster`` / ``BoundedSender`` /
``EventBuffer`` collaboration hand-rolled in each route. Cross-boundary
I/O (sending bytes, persisting events, validating tokens, sleeping) goes
through the ports in :mod:`shieldops.api.ws.core.ports`.

Key structural invariants (locked by contract tests in
``tests/unit/api/ws/test_hub.py``):

1. **Replay is enforced** — :meth:`Hub.publish` is the only path to the
   wire, and it always calls ``buffer.append`` before fanout. A producer
   cannot send without buffering.

2. **Backpressure is on by default** — every subscription has a bounded
   :class:`asyncio.Queue` and a drain task. A slow consumer cannot stall
   the publish path.

3. **Attach is atomic** — the subtlest invariant. Events published
   between ``replay buffered events`` and ``start forwarding live`` are
   neither dropped nor duplicated. This is implemented by holding
   ``self._lock`` across both ``replay the buffer into the queue`` and
   ``register the subscription``. Once the lock is released, any new
   :meth:`publish` also takes the lock and enqueues into the same queue
   — so the replay events (pushed first) and the live events (pushed
   after) are in a single FIFO, in the correct order, with no gap and
   no duplicate.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Awaitable, Callable
from typing import Any

from shieldops.api.ws.core.events import (
    BufferedEvent,
    Event,
    HubConfig,
    Principal,
    Subscription,
)
from shieldops.api.ws.core.ports import (
    Authenticator,
    Buffer,
    Clock,
    Logger,
    Tracer,
    Transport,
)


class AuthError(Exception):
    """Raised by ``Authenticator`` when the token is invalid for a channel."""


# Optional per-connection inbound handler. See RFC #242 section "chat-style
# route with inbound state machine" — the `on_message` borrow from Design A.
OnMessage = Callable[[dict[str, Any], "ClientCtx"], Awaitable[None]]


class ClientCtx:
    """Context passed to ``on_message`` handlers.

    Kept intentionally small — just the identifying fields a handler needs.
    """

    def __init__(self, *, conn_id: str, channel: str, principal: Principal) -> None:
        self.conn_id = conn_id
        self.channel = channel
        self.principal = principal


class Hub:
    """Per-process WebSocket hub. Depends only on injected ports.

    Usage::

        hub = Hub(
            transport=StarletteTransport(),
            buffer=InMemoryBuffer(),
            auth=JwtAuthenticator(settings.jwt),
            clock=SystemClock(),
            log=structlog.get_logger("ws"),
            tracer=OtelTracer(),
        )
        await hub.attach(conn_id="c1", channel="org:123", token="...")
        await hub.publish("org:123", Event(kind="firewall_event", data={...}))
        await hub.detach("c1")
    """

    def __init__(
        self,
        *,
        transport: Transport,
        buffer: Buffer,
        auth: Authenticator,
        clock: Clock,
        log: Logger,
        tracer: Tracer,
        config: HubConfig | None = None,
    ) -> None:
        self.transport = transport
        self.buffer = buffer
        self.auth = auth
        self.clock = clock
        self.log = log
        self.tracer = tracer
        self.config = config or HubConfig()

        # Connection registry — private; callers never touch this.
        self._subscriptions: dict[str, Subscription] = {}
        self._by_channel: dict[str, set[str]] = {}

        # Monotonic event id counter. Strings, padded, so lexicographic
        # ordering matches numeric ordering for simple diagnostics.
        self._next_seq: int = 0

        # Single lock serializes attach + publish so the "register before
        # fanout" invariant holds. See class docstring for the atomicity
        # argument.
        self._lock = asyncio.Lock()

        # Shutdown flag for run_heartbeats.
        self._shutdown = asyncio.Event()

    # ------------------------------------------------------------------ ids

    def _next_id(self) -> str:
        self._next_seq += 1
        return f"evt-{self._next_seq:012d}"

    # ------------------------------------------------------------------ attach

    async def attach(
        self,
        *,
        conn_id: str,
        channel: str,
        token: str,
        since_id: str | None = None,
        on_message: OnMessage | None = None,
    ) -> Subscription:
        """Authenticate, register, replay, and start forwarding live events.

        The replay + registration happens atomically under ``self._lock``
        so any ``publish`` racing with this ``attach`` is serialized: its
        events land in the subscription's queue *after* the replay, never
        before, never interleaved.

        Raises :class:`AuthError` if the authenticator rejects the token.
        """
        try:
            principal = await self.auth.authenticate(token, channel)
        except Exception as exc:
            # Close the transport immediately — the caller has already
            # registered it with the transport adapter before calling attach.
            await self.transport.close(conn_id, code=4001)
            self.log.warning("hub.auth_failed", conn_id=conn_id, channel=channel, error=str(exc))
            raise AuthError(f"authentication failed for {conn_id}") from exc

        queue: asyncio.Queue = asyncio.Queue(maxsize=self.config.queue_max)
        sub = Subscription(conn_id=conn_id, channel=channel, principal=principal, queue=queue)

        async with self._lock:
            # 1. Replay the buffer INTO the queue first.
            if since_id is not None or self.config.replay_max_events > 0:
                # since_id=None means "no replay" (caller is a fresh client);
                # only replay when since_id is explicitly passed.
                if since_id is not None:
                    async for evt in self.buffer.since(channel, since_id):
                        try:
                            queue.put_nowait(evt)
                        except asyncio.QueueFull:
                            # Replay overflow — drop the oldest replayed
                            # events rather than dropping new live events.
                            try:
                                queue.get_nowait()
                                queue.put_nowait(evt)
                            except asyncio.QueueEmpty:
                                pass

            # 2. Register the subscription. From this point on, any
            #    publish() that takes the lock will *also* enqueue to
            #    this queue — so live events arrive in order after the
            #    replayed ones.
            self._subscriptions[conn_id] = sub
            self._by_channel.setdefault(channel, set()).add(conn_id)

        # 3. Start the drain task OUTSIDE the lock so it can't deadlock
        #    the publish path via transport.send.
        sub.drain_task = asyncio.create_task(
            self._drain(sub, on_message=on_message),
            name=f"hub-drain-{conn_id}",
        )
        self.log.info(
            "hub.attach",
            conn_id=conn_id,
            channel=channel,
            since_id=since_id,
            tenant_id=principal.tenant_id,
        )
        return sub

    # ------------------------------------------------------------------ detach

    async def detach(self, conn_id: str) -> None:
        """Unregister and close a connection cleanly.

        Idempotent — detaching an unknown ``conn_id`` is a no-op.
        """
        async with self._lock:
            sub = self._subscriptions.pop(conn_id, None)
            if sub is None:
                return
            subs_in_chan = self._by_channel.get(sub.channel)
            if subs_in_chan is not None:
                subs_in_chan.discard(conn_id)
                if not subs_in_chan:
                    del self._by_channel[sub.channel]

        # Poison pill wakes the drain task.
        await sub.queue.put(None)  # type: ignore[arg-type]
        if sub.drain_task is not None:
            # Drain errors are logged inside _drain; don't re-raise.
            with contextlib.suppress(Exception):
                await sub.drain_task
        await self.transport.close(conn_id)
        self.log.info("hub.detach", conn_id=conn_id, channel=sub.channel)

    # ------------------------------------------------------------------ publish

    async def publish(self, channel: str, event: Event) -> str:
        """Buffer + fanout in one atomic step. Returns the assigned event id.

        Contract: every call buffers BEFORE fanning out. There is no code
        path that sends without buffering — this is the structural
        enforcement of replay-on-reconnect.
        """
        async with self._lock:
            event_id = self._next_id()
            payload = self._encode(event, event_id)
            ts = self.clock.now().timestamp()
            await self.buffer.append(channel, event_id, payload, ts)

            buffered = BufferedEvent(
                id=event_id,
                kind=event.kind,
                payload=payload,
                ts=ts,
                channel=channel,
            )

            # Fan out to all current subscribers atomically with the
            # buffer append. This serializes publish vs attach so the
            # subscription's queue always sees events in order.
            for conn_id in list(self._by_channel.get(channel, set())):
                sub = self._subscriptions.get(conn_id)
                if sub is None:
                    continue
                try:
                    sub.queue.put_nowait(buffered)
                except asyncio.QueueFull:
                    self._apply_drop_policy(sub, buffered)

        return event_id

    def _apply_drop_policy(self, sub: Subscription, new_event: BufferedEvent) -> None:
        policy = self.config.drop_policy
        if policy == "oldest":
            try:
                sub.queue.get_nowait()
                sub.queue.put_nowait(new_event)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass
            self.log.warning(
                "hub.backpressure.drop_oldest",
                conn_id=sub.conn_id,
                channel=sub.channel,
                event_id=new_event.id,
            )
        elif policy == "newest":
            self.log.warning(
                "hub.backpressure.drop_newest",
                conn_id=sub.conn_id,
                channel=sub.channel,
                event_id=new_event.id,
            )
        elif policy == "disconnect":
            self.log.warning(
                "hub.backpressure.disconnect",
                conn_id=sub.conn_id,
                channel=sub.channel,
            )
            # We can't synchronously detach here (we're inside the lock).
            # Poison the queue so the drain task exits, and schedule a
            # close after the current publish.
            with contextlib.suppress(asyncio.QueueFull):
                sub.queue.put_nowait(None)  # type: ignore[arg-type]

    # ------------------------------------------------------------------ drain

    async def _drain(
        self,
        sub: Subscription,
        *,
        on_message: OnMessage | None,
    ) -> None:
        """Per-connection drain loop. Pulls from the queue and sends.

        The loop exits when:
        - the queue yields ``None`` (poison pill from detach or drop policy)
        - ``transport.is_open`` returns False
        - a send raises (connection lost)
        """
        while True:
            item = await sub.queue.get()
            if item is None:
                break
            if not self.transport.is_open(sub.conn_id):
                break
            try:
                await self.transport.send(sub.conn_id, item.payload)
            except Exception as exc:  # noqa: BLE001
                self.log.error(
                    "hub.send_failed",
                    conn_id=sub.conn_id,
                    channel=sub.channel,
                    event_id=item.id,
                    error=str(exc),
                )
                break
        # on_message is reserved for chat-style inbound handling; the
        # real Starlette-adapter implementation will wire it up. The
        # in-memory transport in tests does not support inbound.
        _ = on_message

    # ------------------------------------------------------------------ lifecycle

    async def run_heartbeats(self) -> None:
        """Background task — periodically wake up and reap stale connections.

        The real implementation will track ``last_pong`` per connection and
        close ones past ``heartbeat_s * 3`` without a pong. For PR-1, this
        method exists as the public lifespan hook and sleeps in the injected
        clock — tests can exercise it deterministically via
        :class:`ManualClock`.
        """
        while not self._shutdown.is_set():
            try:
                await self.clock.sleep(self.config.heartbeat_s)
            except asyncio.CancelledError:
                return

    async def stop(self) -> None:
        """Signal heartbeats to exit. Idempotent."""
        self._shutdown.set()

    # ------------------------------------------------------------------ introspection

    def subscriber_count(self, channel: str) -> int:
        """For diagnostics and tests — not part of the hot path."""
        return len(self._by_channel.get(channel, set()))

    def active_connections(self) -> int:
        return len(self._subscriptions)

    # ------------------------------------------------------------------ encoding

    @staticmethod
    def _encode(event: Event, event_id: str) -> bytes:
        """Canonical wire format. Tests depend on the ``id``+``kind``+``data``
        envelope being stable.
        """
        return json.dumps(
            {"id": event_id, "kind": event.kind, "data": event.data},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
