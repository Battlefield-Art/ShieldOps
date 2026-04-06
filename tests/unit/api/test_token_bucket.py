"""Token bucket rate limiter — behavioral tests (#rate_limit_tdd)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from shieldops.api.middleware.token_bucket import TokenBucket


class TestTokenBucketNewBucket:
    """A freshly-created bucket should start full at capacity."""

    @pytest.mark.asyncio
    async def test_new_bucket_allows_up_to_capacity(self) -> None:
        bucket = TokenBucket(capacity=10, refill_rate_per_sec=1.0)
        for _ in range(10):
            allowed, retry_after = await bucket.try_consume("user:alice")
            assert allowed is True
            assert retry_after == 0.0


class TestTokenBucketEmpty:
    """An empty bucket should deny and report how long to wait."""

    @pytest.mark.asyncio
    async def test_empty_bucket_denies_with_positive_retry_after(self) -> None:
        bucket = TokenBucket(capacity=2, refill_rate_per_sec=1.0)
        # drain
        await bucket.try_consume("user:bob")
        await bucket.try_consume("user:bob")
        # next call should be denied
        allowed, retry_after = await bucket.try_consume("user:bob")
        assert allowed is False
        assert retry_after > 0.0
        # refill rate 1/s, deficit is 1 token → retry_after ≈ 1.0
        assert 0.9 <= retry_after <= 1.1


class TestTokenBucketRefill:
    """Bucket should refill at rate * elapsed_seconds on each call."""

    @pytest.mark.asyncio
    async def test_bucket_refills_over_time(self) -> None:
        bucket = TokenBucket(capacity=5, refill_rate_per_sec=2.0)
        with patch("shieldops.api.middleware.token_bucket.time.monotonic", return_value=1000.0):
            # Drain 5 tokens at t=1000
            for _ in range(5):
                assert (await bucket.try_consume("k"))[0] is True
            # Empty
            assert (await bucket.try_consume("k"))[0] is False

        # Advance 2 seconds → refill 4 tokens (2/s * 2s)
        with patch("shieldops.api.middleware.token_bucket.time.monotonic", return_value=1002.0):
            for _ in range(4):
                allowed, _ = await bucket.try_consume("k")
                assert allowed is True
            # 5th call should fail — only 4 refilled
            allowed, _ = await bucket.try_consume("k")
            assert allowed is False

    @pytest.mark.asyncio
    async def test_refill_never_exceeds_capacity(self) -> None:
        """A long idle period must not let the bucket overfill."""
        bucket = TokenBucket(capacity=5, refill_rate_per_sec=10.0)
        with patch("shieldops.api.middleware.token_bucket.time.monotonic", return_value=1000.0):
            await bucket.try_consume("k")  # initialize + take 1 (tokens=4)

        # Advance 1 hour — would refill 36,000 tokens if uncapped
        with patch("shieldops.api.middleware.token_bucket.time.monotonic", return_value=4600.0):
            # Should still only allow 5 in a burst (capped at capacity)
            for _ in range(5):
                assert (await bucket.try_consume("k"))[0] is True
            # 6th is denied
            allowed, _ = await bucket.try_consume("k")
            assert allowed is False


class TestTokenBucketIsolation:
    """Draining one key must not affect other keys."""

    @pytest.mark.asyncio
    async def test_keys_are_independent(self) -> None:
        bucket = TokenBucket(capacity=3, refill_rate_per_sec=1.0)
        # drain alice
        for _ in range(3):
            assert (await bucket.try_consume("alice"))[0] is True
        assert (await bucket.try_consume("alice"))[0] is False
        # bob still has full bucket
        for _ in range(3):
            assert (await bucket.try_consume("bob"))[0] is True
        assert (await bucket.try_consume("bob"))[0] is False


class TestTokenBucketMultiToken:
    """Requests can consume more than 1 token at a time (weighted)."""

    @pytest.mark.asyncio
    async def test_weighted_consume(self) -> None:
        bucket = TokenBucket(capacity=10, refill_rate_per_sec=1.0)
        # Consume 7 tokens at once
        allowed, _ = await bucket.try_consume("k", tokens=7)
        assert allowed is True
        # Only 3 left
        allowed, _ = await bucket.try_consume("k", tokens=5)
        assert allowed is False
        # Can consume 3
        allowed, _ = await bucket.try_consume("k", tokens=3)
        assert allowed is True
        # Now empty
        allowed, _ = await bucket.try_consume("k", tokens=1)
        assert allowed is False

    def test_invalid_capacity_rejected(self) -> None:
        with pytest.raises(ValueError, match="capacity must be > 0"):
            TokenBucket(capacity=0, refill_rate_per_sec=1.0)

    def test_invalid_rate_rejected(self) -> None:
        with pytest.raises(ValueError, match="refill_rate"):
            TokenBucket(capacity=5, refill_rate_per_sec=0)


class TestTokenBucketMiddleware:
    """HTTP middleware returns 429 with Retry-After header when bucket is empty."""

    def test_middleware_429_with_retry_after_header(self) -> None:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from shieldops.api.middleware.token_bucket import TokenBucketMiddleware

        app = FastAPI()
        app.add_middleware(
            TokenBucketMiddleware,
            capacity=2,
            refill_rate_per_sec=1.0,
            key_fn=lambda req: "test",
        )

        @app.get("/ping")
        def ping() -> dict[str, str]:
            return {"ok": "yes"}

        client = TestClient(app)
        # First 2 OK
        assert client.get("/ping").status_code == 200
        assert client.get("/ping").status_code == 200
        # Third is 429 with Retry-After
        r = client.get("/ping")
        assert r.status_code == 429
        assert "Retry-After" in r.headers
        assert int(r.headers["Retry-After"]) >= 1
