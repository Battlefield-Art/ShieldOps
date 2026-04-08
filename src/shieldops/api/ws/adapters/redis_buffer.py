"""Redis-backed ``Buffer`` adapter — RFC #242 PR-5 / #259.

Multi-replica deployments need the WebSocket Hub's replay-on-reconnect
window to be shared across all replicas of the ShieldOps API pod. A
client that reconnects to a *different* replica must still receive
events published while it was disconnected, regardless of which replica
actually handled the original ``Hub.publish`` call.

Design
======

**Topology.** One Redis Stream per channel, keyed
``ws:buffer:{channel}``. ``Buffer.append`` performs ``XADD`` with a
``MAXLEN ~ <max_per_channel>`` trim directive so the stream self-evicts
its oldest entries without a separate background sweeper. ``Buffer.since``
resolves the supplied ``since_id`` to a Redis stream id (stored as a
per-event field on ``XADD``) and issues ``XRANGE`` for the matching
entries. ``Buffer.trim`` is a no-op beyond what ``MAXLEN ~`` already
enforces on the append path.

**Why Streams and not a sorted set?** Streams give us:

- Native trim semantics (``MAXLEN ~``) in a single round-trip per append,
  so the hot path is one command.
- Server-assigned monotonic stream ids, which we pair with the Hub's
  own ``event_id`` for exactly-once replay addressing.
- Multi-replica reads without any locking — ``XRANGE`` is safe to call
  concurrently from every replica.

**Why not use this for cross-replica fan-out?** Streams are persistent
storage, not pub/sub. Live fan-out across replicas uses Redis pub/sub in
:mod:`shieldops.api.ws.adapters.redis_hub_bridge` — a composition-layer
helper that does not touch the Hub core.

**SDK hygiene.** This module imports ``redis.asyncio`` only. No Redis
types leak into :mod:`shieldops.api.ws.core` — the core only sees the
:class:`shieldops.api.ws.core.ports.Buffer` protocol. SHOP-003 passes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

from shieldops.api.ws.core.events import BufferedEvent

if TYPE_CHECKING:
    from redis.asyncio import Redis


class RedisBuffer:
    """Redis Streams backed :class:`Buffer` adapter.

    One stream per channel, key ``ws:buffer:{channel}``. Append performs
    a ``MAXLEN ~`` trimmed ``XADD``; replay is an ``XRANGE`` call.

    The stream field layout is::

        event_id: str   (Hub-assigned, e.g. ``evt-000000000123``)
        payload:  bytes (already-encoded JSON envelope)
        ts:       float (seconds since epoch, as string)
        channel:  str

    The Redis stream id (``<ms>-<seq>``) is never exposed to the Hub
    core — only the Hub's own ``event_id`` round-trips.
    """

    _KEY_PREFIX = "ws:buffer:"

    def __init__(self, redis: Redis, *, max_per_channel: int = 1000) -> None:
        if max_per_channel <= 0:
            raise ValueError("max_per_channel must be positive")
        self._redis = redis
        self._max = max_per_channel

    def _key(self, channel: str) -> str:
        return f"{self._KEY_PREFIX}{channel}"

    async def append(
        self,
        channel: str,
        event_id: str,
        payload: bytes,
        ts: float,
    ) -> None:
        fields: dict[str | bytes, Any] = {
            "event_id": event_id,
            "payload": payload,
            "ts": str(ts),
            "channel": channel,
        }
        await self._redis.xadd(
            self._key(channel),
            fields,
            maxlen=self._max,
            approximate=True,
        )

    async def since(
        self,
        channel: str,
        since_id: str | None,
    ) -> AsyncIterator[BufferedEvent]:
        """Yield events strictly newer than ``since_id``.

        Contract (matches :class:`InMemoryBuffer`):

        - ``since_id=None``           → yield the entire current window.
        - ``since_id`` not found      → yield the entire current window.
        - ``since_id`` found          → yield events after that id.
        """
        entries = await self._redis.xrange(self._key(channel), min="-", max="+")
        if not entries:
            return

        # Decode entries into BufferedEvents in stream order.
        decoded: list[BufferedEvent] = []
        for _stream_id, raw_fields in entries:
            decoded.append(_decode_entry(channel, raw_fields))

        if since_id is None:
            for evt in decoded:
                yield evt
            return

        found_index: int | None = None
        for i, evt in enumerate(decoded):
            if evt.id == since_id:
                found_index = i
                break

        if found_index is None:
            for evt in decoded:
                yield evt
            return

        for evt in decoded[found_index + 1 :]:
            yield evt

    async def trim(
        self,
        channel: str,
        max_age_s: float,
        max_len: int,
    ) -> None:
        """Enforce ``max_len`` explicitly via ``XTRIM MAXLEN ~``.

        ``max_age_s`` is not enforced here: Redis Streams does not support
        TTL-on-entry. The append path's ``MAXLEN ~ max_per_channel``
        already bounds memory; age-based eviction is deferred to a
        future sweeper if/when product requirements call for it.
        """
        if max_len <= 0:
            return
        await self._redis.xtrim(
            self._key(channel),
            maxlen=max_len,
            approximate=True,
        )


def _decode_entry(channel: str, raw: dict[Any, Any]) -> BufferedEvent:
    """Decode a raw Redis stream entry to a :class:`BufferedEvent`.

    ``redis.asyncio`` returns byte-keyed dicts unless the client is
    configured with ``decode_responses=True``. We tolerate both shapes
    so callers don't have to pre-configure their client.
    """

    def _get(key: str) -> Any:
        if key in raw:
            return raw[key]
        b = key.encode("utf-8")
        return raw.get(b)

    event_id_raw = _get("event_id")
    payload_raw = _get("payload")
    ts_raw = _get("ts")
    channel_raw = _get("channel")

    event_id = (
        event_id_raw.decode("utf-8") if isinstance(event_id_raw, bytes) else str(event_id_raw)
    )
    payload = payload_raw if isinstance(payload_raw, bytes) else str(payload_raw).encode("utf-8")
    ts_str = ts_raw.decode("utf-8") if isinstance(ts_raw, bytes) else str(ts_raw)
    ts = float(ts_str) if ts_str else 0.0
    chan = (
        channel_raw.decode("utf-8")
        if isinstance(channel_raw, bytes)
        else (str(channel_raw) if channel_raw is not None else channel)
    )

    return BufferedEvent(
        id=event_id,
        kind="",
        payload=payload,
        ts=ts,
        channel=chan,
    )
