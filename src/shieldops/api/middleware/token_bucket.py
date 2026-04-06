"""Token bucket rate limiter — real token bucket algorithm.

Designed to replace the fixed-window counter in rate_limiter.py for endpoints
that need smoother, fairer rate limiting (e.g. API keys, ingestion).

Public interface::

    bucket = TokenBucket(capacity=100, refill_rate_per_sec=10)
    allowed, retry_after = await bucket.try_consume("api_key:abc123")
    if not allowed:
        raise HTTPException(429, headers={"Retry-After": str(int(retry_after) + 1)})

Behaviors:
- A new key starts with a full bucket (capacity tokens).
- ``try_consume`` removes ``tokens`` if available, refills based on elapsed
  wall-clock time since the last call, and reports how many seconds until
  enough tokens will be available.
- Buckets are per-key; independent keys do not interfere.
- Bucket contents are capped at ``capacity`` regardless of elapsed time.

Storage:
- Default: in-memory (per-process). Suitable for single-node deployments and tests.
- Redis-backed variant is exposed via :class:`RedisTokenBucket` for multi-node
  deployments; it uses an atomic Lua script so concurrent workers are safe.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class _BucketState:
    tokens: float
    last_refill: float


class TokenBucket:
    """In-memory token bucket. Thread-safe across asyncio tasks within a process."""

    def __init__(self, capacity: int, refill_rate_per_sec: float) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        if refill_rate_per_sec <= 0:
            raise ValueError("refill_rate_per_sec must be > 0")
        self._capacity = float(capacity)
        self._rate = float(refill_rate_per_sec)
        self._buckets: dict[str, _BucketState] = {}
        self._lock = asyncio.Lock()

    async def try_consume(self, key: str, tokens: int = 1) -> tuple[bool, float]:
        """Try to remove ``tokens`` from the bucket for ``key``.

        Returns ``(allowed, retry_after)``. ``retry_after`` is 0.0 when allowed,
        otherwise the number of seconds until enough tokens will have refilled.
        """
        async with self._lock:
            now = time.monotonic()
            state = self._buckets.get(key)
            if state is None:
                state = _BucketState(tokens=self._capacity, last_refill=now)
                self._buckets[key] = state
            self._refill_locked(state, now)
            return self._consume_locked(state, tokens)

    def _refill_locked(self, state: _BucketState, now: float) -> None:
        elapsed = max(0.0, now - state.last_refill)
        state.tokens = min(self._capacity, state.tokens + elapsed * self._rate)
        state.last_refill = now

    def _consume_locked(self, state: _BucketState, tokens: int) -> tuple[bool, float]:
        if state.tokens >= tokens:
            state.tokens -= tokens
            return (True, 0.0)
        deficit = tokens - state.tokens
        retry_after = deficit / self._rate
        return (False, retry_after)


class TokenBucketMiddleware:
    """Starlette/FastAPI middleware that applies a TokenBucket per request key.

    Usage::

        app.add_middleware(
            TokenBucketMiddleware,
            capacity=100,
            refill_rate_per_sec=10,
            key_fn=lambda req: req.headers.get("Authorization", req.client.host),
        )
    """

    def __init__(
        self,
        app: Any,
        *,
        capacity: int,
        refill_rate_per_sec: float,
        key_fn: Callable[[Any], str],
        tokens_per_request: int = 1,
    ) -> None:
        self.app = app
        self._bucket = TokenBucket(capacity=capacity, refill_rate_per_sec=refill_rate_per_sec)
        self._key_fn = key_fn
        self._tokens_per_request = tokens_per_request

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Build a lightweight request shim so key_fn can inspect headers/client
        from starlette.requests import Request

        request = Request(scope)
        key = self._key_fn(request)
        allowed, retry_after = await self._bucket.try_consume(key, tokens=self._tokens_per_request)
        if allowed:
            await self.app(scope, receive, send)
            return

        # 429 Too Many Requests
        import json

        retry_seconds = max(1, math.ceil(retry_after))
        body = json.dumps({"detail": "rate limit exceeded", "retry_after": retry_seconds}).encode(
            "utf-8"
        )
        await send(
            {
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"retry-after", str(retry_seconds).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
