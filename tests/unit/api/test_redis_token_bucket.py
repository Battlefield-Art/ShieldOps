"""Redis-backed token bucket — TDD tests (#4-redis).

Uses a tiny in-memory fake Redis that implements just enough of the redis
aio interface (eval, get, set, delete) for the Lua-script implementation.
"""

from __future__ import annotations

from typing import Any

import pytest

from shieldops.api.middleware.token_bucket import RedisTokenBucket


class _FakeRedis:
    """Minimal async Redis stand-in with eval() supporting the bucket script."""

    def __init__(self) -> None:
        self.store: dict[str, Any] = {}
        self.now = 1000.0  # monotonic clock we control

    async def eval(self, script: str, numkeys: int, *args: Any) -> Any:
        # The bucket script signature is: KEYS=[key], ARGV=[capacity, rate, tokens, now]
        key = args[0]
        capacity = float(args[1])
        rate = float(args[2])
        tokens_requested = float(args[3])
        now = float(args[4])

        state = self.store.get(key)
        if state is None:
            tokens = capacity
            last = now
        else:
            tokens = state["tokens"]
            last = state["last"]
            elapsed = max(0.0, now - last)
            tokens = min(capacity, tokens + elapsed * rate)
            last = now

        if tokens >= tokens_requested:
            tokens -= tokens_requested
            self.store[key] = {"tokens": tokens, "last": last}
            return [1, 0.0]  # allowed, retry_after
        deficit = tokens_requested - tokens
        retry_after = deficit / rate
        self.store[key] = {"tokens": tokens, "last": last}
        return [0, retry_after]


@pytest.fixture()
def redis() -> _FakeRedis:
    return _FakeRedis()


class TestRedisTokenBucketBasic:
    @pytest.mark.asyncio
    async def test_new_bucket_allows_up_to_capacity(self, redis: _FakeRedis) -> None:
        bucket = RedisTokenBucket(redis_client=redis, capacity=5, refill_rate_per_sec=1.0)
        for _ in range(5):
            allowed, retry = await bucket.try_consume("k")
            assert allowed is True
            assert retry == 0.0

    @pytest.mark.asyncio
    async def test_empty_bucket_denies(self, redis: _FakeRedis) -> None:
        bucket = RedisTokenBucket(redis_client=redis, capacity=2, refill_rate_per_sec=1.0)
        await bucket.try_consume("k")
        await bucket.try_consume("k")
        allowed, retry = await bucket.try_consume("k")
        assert allowed is False
        assert retry > 0.0

    @pytest.mark.asyncio
    async def test_independent_keys(self, redis: _FakeRedis) -> None:
        bucket = RedisTokenBucket(redis_client=redis, capacity=2, refill_rate_per_sec=1.0)
        for _ in range(2):
            assert (await bucket.try_consume("a"))[0] is True
        assert (await bucket.try_consume("a"))[0] is False
        # b unaffected
        assert (await bucket.try_consume("b"))[0] is True
        assert (await bucket.try_consume("b"))[0] is True


class TestRedisTokenBucketMultiWorker:
    """Two worker processes sharing the same Redis must not double-spend."""

    @pytest.mark.asyncio
    async def test_two_workers_share_state(self, redis: _FakeRedis) -> None:
        bucket_a = RedisTokenBucket(redis_client=redis, capacity=3, refill_rate_per_sec=1.0)
        bucket_b = RedisTokenBucket(redis_client=redis, capacity=3, refill_rate_per_sec=1.0)
        # 3 consumes total across 2 workers should exhaust the bucket
        assert (await bucket_a.try_consume("shared"))[0] is True
        assert (await bucket_b.try_consume("shared"))[0] is True
        assert (await bucket_a.try_consume("shared"))[0] is True
        # Fourth is denied regardless of which worker asks
        assert (await bucket_b.try_consume("shared"))[0] is False
        assert (await bucket_a.try_consume("shared"))[0] is False
