"""Atomic get_or_set on InMemoryIdempotencyStore — TDD tests (#7 Round 3).

Existing get → call_next → set has a race window where two concurrent
requests with the same key can both execute the factory. ``get_or_set``
makes the compute-or-return atomic per key.
"""

from __future__ import annotations

import asyncio

import pytest

from shieldops.api.middleware.idempotency import InMemoryIdempotencyStore


@pytest.fixture()
def store() -> InMemoryIdempotencyStore:
    return InMemoryIdempotencyStore()


class TestGetOrSet:
    @pytest.mark.asyncio
    async def test_first_call_invokes_factory(self, store: InMemoryIdempotencyStore) -> None:
        called = {"n": 0}

        async def factory() -> dict[str, int]:
            called["n"] += 1
            return {"v": 42}

        result = await store.get_or_set("k1", ttl=60, factory=factory)
        assert result == {"v": 42}
        assert called["n"] == 1

    @pytest.mark.asyncio
    async def test_second_call_returns_cached_without_factory(
        self, store: InMemoryIdempotencyStore
    ) -> None:
        called = {"n": 0}

        async def factory() -> dict[str, int]:
            called["n"] += 1
            return {"v": 42}

        await store.get_or_set("k1", ttl=60, factory=factory)
        result = await store.get_or_set("k1", ttl=60, factory=factory)
        assert result == {"v": 42}
        assert called["n"] == 1  # factory only ran once

    @pytest.mark.asyncio
    async def test_concurrent_calls_only_run_factory_once(
        self, store: InMemoryIdempotencyStore
    ) -> None:
        runs = {"n": 0}

        async def slow_factory() -> dict[str, int]:
            runs["n"] += 1
            await asyncio.sleep(0.05)  # Hold the lock briefly
            return {"v": runs["n"]}

        results = await asyncio.gather(
            *[store.get_or_set("race", ttl=60, factory=slow_factory) for _ in range(10)]
        )
        # All callers must see the same value …
        assert all(r == {"v": 1} for r in results)
        # … and the factory must only have run once.
        assert runs["n"] == 1

    @pytest.mark.asyncio
    async def test_concurrent_calls_with_different_keys_run_independently(
        self, store: InMemoryIdempotencyStore
    ) -> None:
        async def factory(value: int) -> dict[str, int]:
            return {"v": value}

        results = await asyncio.gather(
            store.get_or_set("a", ttl=60, factory=lambda: factory(1)),
            store.get_or_set("b", ttl=60, factory=lambda: factory(2)),
        )
        assert results == [{"v": 1}, {"v": 2}]

    @pytest.mark.asyncio
    async def test_factory_failure_does_not_poison_cache(
        self, store: InMemoryIdempotencyStore
    ) -> None:
        async def boom() -> dict[str, int]:
            raise RuntimeError("kaboom")

        with pytest.raises(RuntimeError):
            await store.get_or_set("k1", ttl=60, factory=boom)

        async def good() -> dict[str, int]:
            return {"v": 7}

        # A subsequent call should be allowed to retry — failure must not
        # be cached.
        result = await store.get_or_set("k1", ttl=60, factory=good)
        assert result == {"v": 7}
