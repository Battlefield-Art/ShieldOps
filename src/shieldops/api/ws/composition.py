"""Composition root for the WebSocket Hub — #242 PR-2.

See ghantakiran/ShieldOps#242. PR-1 landed the pure :class:`Hub` core
over injected ports + in-memory adapters + contract tests. This module
is the PR-2 composition root that the FastAPI layer uses to reach the
installed hub via ``Depends(get_ws_hub)``.

Same shape as :mod:`shieldops.api.policy.composition`,
:mod:`shieldops.utils.evolution.composition`, and
:mod:`shieldops.licensing.composition`:

- :func:`set_ws_hub` installs (or clears) the process-wide hub.
- :func:`get_ws_hub` returns it or raises ``RuntimeError`` — route code
  uses ``Depends(get_ws_hub)``.
- :func:`build_in_memory_hub` assembles a fully-defaulted hub with all
  the in-memory adapters PR-1 shipped. Used by tests + by the lifespan
  hook in environments where the real Starlette transport hasn't been
  wired yet.
- :func:`use_test_ws_hub` swaps in a test hub for the duration of a
  block, restoring the previous one on exit (including exception paths).

Production adapters (``StarletteTransport``, ``JwtAuthenticator``,
``SystemClock``, ``StructlogLogger``, ``OtelTracer``) land in PR-3 and
will be reached via a separate ``build_production_hub`` factory that
wires real SDK-backed ports. The process-wide setter is the same so
both paths fit the same ``Depends(get_ws_hub)`` contract.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from shieldops.api.ws.adapters import (
    InMemoryBuffer,
    InMemoryTransport,
    ManualClock,
    NullLogger,
    NullTracer,
    RedisBuffer,
    RedisHubBridge,
    StaticTokenAuthenticator,
)
from shieldops.api.ws.core import Hub, HubConfig, Principal
from shieldops.api.ws.core.events import Event

if TYPE_CHECKING:
    from redis.asyncio import Redis

__all__ = [
    "build_in_memory_hub",
    "build_redis_hub",
    "get_ws_hub",
    "select_hub_backend",
    "set_ws_hub",
    "use_test_ws_hub",
]


_hub: Hub | None = None


def set_ws_hub(hub: Hub | None) -> None:
    """Install (or clear) the process-wide WebSocket hub."""
    global _hub
    _hub = hub


def get_ws_hub() -> Hub:
    """Return the installed hub or raise :class:`RuntimeError`.

    This is the FastAPI dependency callable: route code uses it via
    ``Depends(get_ws_hub)`` to reach the single shared hub instance.
    """
    if _hub is None:
        raise RuntimeError(
            "No WebSocket Hub installed. Call set_ws_hub(hub) during app "
            "startup, or use `use_test_ws_hub()` in tests."
        )
    return _hub


def build_in_memory_hub(
    *,
    config: HubConfig | None = None,
    start_ts: float = 0.0,
    tokens: dict[str, Principal] | None = None,
) -> Hub:
    """Build a fully-defaulted hub with all in-memory adapters.

    Args:
        config: Optional HubConfig override. Defaults to :class:`HubConfig`
            factory defaults.
        start_ts: Initial ``ManualClock`` timestamp.
        tokens: Optional mapping of ``token → Principal`` used by
            :class:`StaticTokenAuthenticator`. When ``None``, an empty
            map is used so every auth call raises — fine for tests that
            never attach; callers will usually pass an explicit map.

    Returns:
        A fully-wired :class:`Hub` ready for :meth:`Hub.attach` calls.
    """
    return Hub(
        transport=InMemoryTransport(),
        buffer=InMemoryBuffer(),
        auth=StaticTokenAuthenticator(tokens=tokens or {}),
        clock=ManualClock(start=start_ts),
        log=NullLogger(),
        tracer=NullTracer(),
        config=config,
    )


async def build_redis_hub(
    *,
    redis_client: Redis,
    config: HubConfig | None = None,
    start_ts: float = 0.0,
    tokens: dict[str, Principal] | None = None,
    max_per_channel: int = 1000,
    replica_id: str | None = None,
) -> tuple[Hub, RedisHubBridge]:
    """Build a Hub wired with the Redis buffer + cross-replica pub/sub bridge.

    Returns a ``(hub, bridge)`` tuple. The caller owns the bridge's
    lifecycle and must ``await bridge.stop()`` during teardown.

    The returned Hub's ``publish`` method is monkey-patched at the
    instance level to tee every local publish onto the Redis bus via
    ``bridge.publish_remote``. This is the minimum-intrusion way to
    avoid modifying the Hub core (SHOP-003 / RFC #242 constraint).
    """
    hub = Hub(
        transport=InMemoryTransport(),
        buffer=RedisBuffer(redis_client, max_per_channel=max_per_channel),
        auth=StaticTokenAuthenticator(tokens=tokens or {}),
        clock=ManualClock(start=start_ts),
        log=NullLogger(),
        tracer=NullTracer(),
        config=config,
    )
    bridge = RedisHubBridge(hub=hub, redis=redis_client, replica_id=replica_id)
    await bridge.start()

    # Tee local publishes onto Redis pub/sub so peer replicas see them.
    original_publish = hub.publish

    async def bridged_publish(channel: str, event: Event) -> str:
        event_id = await original_publish(channel, event)
        payload = Hub._encode(event, event_id)
        ts = hub.clock.now().timestamp()
        with contextlib.suppress(Exception):
            await bridge.publish_remote(
                channel,
                event_id=event_id,
                payload=payload,
                kind=event.kind,
                ts=ts,
            )
        return event_id

    hub.publish = bridged_publish  # type: ignore[method-assign]
    return hub, bridge


def select_hub_backend(settings: Any) -> str:
    """Return which hub backend to use: ``"redis"`` or ``"memory"``.

    Selection rule: Redis is used when ``settings.ws_hub_backend == "redis"``
    (explicit opt-in). This keeps single-replica deployments on the
    in-memory hub by default — flipping to Redis without an explicit
    config change would be a surprising behavioral shift for every
    existing ShieldOps install.
    """
    backend = getattr(settings, "ws_hub_backend", "memory")
    if backend not in {"memory", "redis"}:
        return "memory"
    return backend


@contextlib.contextmanager
def use_test_ws_hub(hub: Hub | None = None) -> Iterator[Hub]:
    """Swap in a test hub for the duration of a block.

    Restores the previous hub on exit, **even on exception**.
    """
    previous = _hub
    fresh = hub or build_in_memory_hub()
    try:
        set_ws_hub(fresh)
        yield fresh
    finally:
        set_ws_hub(previous)
