"""Redis pub/sub bridge for cross-replica :class:`Hub` fan-out — PR-5.

Background
==========

:class:`shieldops.api.ws.core.hub.Hub` fans out events to the local
subscribers it knows about — ``hub._by_channel``. In a single-replica
deployment that is the whole universe of subscribers. In a multi-replica
deployment, each replica has its *own* hub with its *own* subscriber set;
a publish on replica A will never reach a subscriber attached to replica
B unless the replicas cooperate.

:class:`RedisHubBridge` is the cooperation layer. It does two things:

1. **Outbound.** After a local ``Hub.publish``, forward the same event
   over Redis pub/sub (``ws:bus:{channel}``) so every other replica's
   bridge receives it.
2. **Inbound.** Subscribe to ``ws:bus:*`` and, on each message, deliver
   the event to the **local** subscribers of the matching channel —
   *without* going back through ``Hub.publish`` (which would re-buffer
   and re-emit on Redis, causing an infinite loop).

Inbound delivery enqueues :class:`BufferedEvent` instances directly into
the subscription's drain queue. This does read ``hub._by_channel`` and
``hub._subscriptions`` from the adapter layer — those fields are
private-by-convention inside the core but are treated as the
composition-root contact surface for cross-replica wiring. The
alternative (a new public ``Hub._deliver_local`` method) would be a
breaking core change that PR-5 is explicitly constrained to avoid.

Loop prevention
===============

The bridge uses an ``origin`` field on every outbound message
(``{"origin": <replica_id>, ...}``). Inbound messages whose ``origin``
matches our own replica id are dropped — that way replica A does not
re-deliver its own outbound publish to itself. Replicas are identified
by a random UUID assigned at bridge construction.

Topology choices
================

- **One channel per topic.** ``ws:bus:{channel}``. Lets Redis do the
  filtering; each replica only wakes up for channels it cares about.
  We subscribe with a pattern (``PSUBSCRIBE ws:bus:*``) so new channels
  don't require re-subscription — at the cost of one extra dict lookup
  per delivered message to strip the prefix.
- **Replay is not the bridge's job.** Replay-on-reconnect is served by
  :class:`shieldops.api.ws.adapters.redis_buffer.RedisBuffer`. The
  bridge only carries live fan-out.

SDK hygiene
===========

``redis.asyncio`` is imported only here and in
:mod:`shieldops.api.ws.adapters.redis_buffer`. The Hub core sees neither.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from typing import TYPE_CHECKING, Any

from shieldops.api.ws.core.events import BufferedEvent
from shieldops.api.ws.core.hub import Hub

if TYPE_CHECKING:
    from redis.asyncio import Redis
    from redis.asyncio.client import PubSub


_CHANNEL_PREFIX = "ws:bus:"
_PATTERN = f"{_CHANNEL_PREFIX}*"


class RedisHubBridge:
    """Cross-replica pub/sub glue for a local :class:`Hub`.

    Usage::

        bridge = RedisHubBridge(hub=hub, redis=redis_client)
        await bridge.start()
        ...
        await bridge.publish_remote(channel, event_id, payload, kind, ts)
        ...
        await bridge.stop()

    The bridge owns a background asyncio task that drains the Redis
    ``PSUBSCRIBE`` iterator. It is safe to call :meth:`stop` multiple
    times; each call after the first is a no-op.
    """

    def __init__(
        self,
        *,
        hub: Hub,
        redis: Redis,
        replica_id: str | None = None,
    ) -> None:
        self._hub = hub
        self._redis = redis
        self._replica_id = replica_id or uuid.uuid4().hex
        self._pubsub: PubSub | None = None
        self._task: asyncio.Task[None] | None = None
        self._stopped = asyncio.Event()

    @property
    def replica_id(self) -> str:
        return self._replica_id

    async def start(self) -> None:
        """Begin draining the Redis pub/sub pattern subscription."""
        if self._task is not None:
            return
        self._pubsub = self._redis.pubsub()
        await self._pubsub.psubscribe(_PATTERN)
        self._hub.log.info(
            "ws.redis_bridge.started",
            replica_id=self._replica_id,
            pattern=_PATTERN,
        )
        self._task = asyncio.create_task(self._run(), name="ws-redis-bridge")

    async def stop(self) -> None:
        """Drain + unsubscribe + cancel the background task. Idempotent."""
        self._stopped.set()
        if self._pubsub is not None:
            with contextlib.suppress(Exception):
                await self._pubsub.punsubscribe(_PATTERN)
            with contextlib.suppress(Exception):
                await self._pubsub.aclose()
            self._pubsub = None
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(BaseException):
                await self._task
            self._task = None
        self._hub.log.info("ws.redis_bridge.stopped", replica_id=self._replica_id)

    async def publish_remote(
        self,
        channel: str,
        *,
        event_id: str,
        payload: bytes,
        kind: str,
        ts: float,
    ) -> None:
        """Broadcast a locally-published event to every other replica.

        Called by :meth:`shieldops.api.ws.composition.build_redis_hub`
        wiring after a local ``Hub.publish`` completes — see the
        ``BridgedHub`` wrapper there. The message carries our replica
        id so we can drop the loopback on inbound.
        """
        message = json.dumps(
            {
                "origin": self._replica_id,
                "event_id": event_id,
                "kind": kind,
                "payload_b64": payload.decode("utf-8"),
                "ts": ts,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        await self._redis.publish(f"{_CHANNEL_PREFIX}{channel}", message)

    async def _run(self) -> None:
        """Background loop: drain pub/sub messages until stopped."""
        assert self._pubsub is not None
        try:
            while not self._stopped.is_set():
                try:
                    msg = await self._pubsub.get_message(
                        ignore_subscribe_messages=True,
                        timeout=1.0,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    # Connection blip — log and keep looping. Reconnect
                    # is handled by redis.asyncio's built-in pool.
                    self._hub.log.warning(
                        "ws.redis_bridge.recv_error",
                        replica_id=self._replica_id,
                        error=str(exc),
                    )
                    await asyncio.sleep(0.5)
                    continue
                if msg is None:
                    continue
                await self._handle_message(msg)
        except asyncio.CancelledError:
            return

    async def _handle_message(self, msg: dict[str, Any]) -> None:
        raw_channel = msg.get("channel")
        data = msg.get("data")
        if raw_channel is None or data is None:
            return
        channel_str = (
            raw_channel.decode("utf-8") if isinstance(raw_channel, bytes) else str(raw_channel)
        )
        if not channel_str.startswith(_CHANNEL_PREFIX):
            return
        topic = channel_str[len(_CHANNEL_PREFIX) :]

        try:
            body_bytes = data if isinstance(data, bytes) else str(data).encode("utf-8")
            body = json.loads(body_bytes)
        except Exception as exc:  # noqa: BLE001
            self._hub.log.warning(
                "ws.redis_bridge.decode_error",
                error=str(exc),
                channel=topic,
            )
            return

        if body.get("origin") == self._replica_id:
            # Loopback — drop.
            return

        buffered = BufferedEvent(
            id=str(body.get("event_id", "")),
            kind=str(body.get("kind", "")),
            payload=str(body.get("payload_b64", "")).encode("utf-8"),
            ts=float(body.get("ts", 0.0)),
            channel=topic,
        )
        self._deliver_local(topic, buffered)

    def _deliver_local(self, channel: str, buffered: BufferedEvent) -> None:
        """Enqueue a remote-origin event into every local subscriber's queue.

        Does **not** call ``Hub.publish`` — that would re-buffer and
        re-broadcast on Redis, forming a loop. Instead, this walks the
        Hub's per-channel subscription set and puts the event onto each
        subscription's drain queue, matching the shape
        ``Hub.publish`` uses internally.
        """
        by_channel = self._hub._by_channel.get(channel)
        if not by_channel:
            return
        for conn_id in list(by_channel):
            sub = self._hub._subscriptions.get(conn_id)
            if sub is None:
                continue
            try:
                sub.queue.put_nowait(buffered)
            except asyncio.QueueFull:
                # Delegate to the core's configured drop policy by
                # reusing its private helper — keeps the backpressure
                # decision in one place.
                self._hub._apply_drop_policy(sub, buffered)
