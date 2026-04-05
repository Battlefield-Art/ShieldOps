"""Redis caching layer for Agent Firewall decisions — latency-critical path.

Provides sub-millisecond lookups for repeated firewall evaluations by caching
allow/block decisions, behavioral baselines, circuit breaker state, and
per-agent rate counters. Falls back to an in-process dict when Redis is
unavailable (fail-open with degraded performance).
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

import structlog

logger = structlog.get_logger()


class FirewallDecisionCache:
    """Cache firewall allow/block decisions for fast repeated lookups.

    Key patterns
    ------------
    - ``fw:decision:{agent_id}:{tool_name}:{args_hash}`` -- cached verdict
    - ``fw:baseline:{agent_id}`` -- serialized behavioral baseline
    - ``fw:circuit:{agent_id}`` -- circuit breaker state (closed/open/half_open)
    - ``fw:rate:{agent_id}:{minute}`` -- call count in current minute window

    Parameters
    ----------
    redis_client:
        An async Redis client (``redis.asyncio.Redis``). If ``None``, the cache
        operates in local-fallback mode using an in-process dict.
    decision_ttl:
        TTL in seconds for cached firewall decisions.
    baseline_ttl:
        TTL in seconds for cached behavioral baselines.
    circuit_ttl:
        TTL in seconds for circuit breaker state. ``0`` means no expiry
        (state persists until explicit reset).
    """

    def __init__(
        self,
        redis_client: Any = None,
        decision_ttl: int = 60,
        baseline_ttl: int = 300,
        circuit_ttl: int = 0,
    ) -> None:
        self._redis = redis_client
        self._decision_ttl = decision_ttl
        self._baseline_ttl = baseline_ttl
        self._circuit_ttl = circuit_ttl
        self._local_cache: dict[str, tuple[Any, float]] = {}
        self._stats = {"hits": 0, "misses": 0, "errors": 0, "local_fallback": 0}

    # ── Key helpers ───────────────────────────────────────────────

    @staticmethod
    def _key(*parts: str) -> str:
        """Build a namespaced cache key."""
        return "fw:" + ":".join(parts)

    @staticmethod
    def hash_args(args: dict[str, Any]) -> str:
        """Produce a short deterministic hash of tool call arguments."""
        serialized = json.dumps(args, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()[:16]

    # ── Local-fallback helpers ────────────────────────────────────

    def _local_get(self, key: str) -> Any | None:
        """Read from the in-process fallback cache."""
        if key in self._local_cache:
            val, expiry = self._local_cache[key]
            if expiry == 0 or time.time() < expiry:
                self._stats["local_fallback"] += 1
                return val
            del self._local_cache[key]
        return None

    def _local_set(self, key: str, value: Any, ttl: int) -> None:
        """Write to the in-process fallback cache."""
        expiry = 0.0 if ttl == 0 else time.time() + ttl
        self._local_cache[key] = (value, expiry)

    # ── Decision cache ────────────────────────────────────────────

    async def get_decision(
        self,
        agent_id: str,
        tool_name: str,
        args_hash: str,
    ) -> dict[str, Any] | None:
        """Get a cached firewall decision. Returns ``None`` on miss."""
        key = self._key("decision", agent_id, tool_name, args_hash)
        try:
            if self._redis:
                raw = await self._redis.get(key)
                if raw:
                    self._stats["hits"] += 1
                    return json.loads(raw)  # type: ignore[no-any-return]
            # Local fallback
            local = self._local_get(key)
            if local is not None:
                self._stats["hits"] += 1
                return local  # type: ignore[no-any-return]
        except Exception:
            self._stats["errors"] += 1
            logger.debug("firewall_cache.get_decision_error", key=key)
            # Try local even on Redis error
            local = self._local_get(key)
            if local is not None:
                self._stats["hits"] += 1
                return local  # type: ignore[no-any-return]

        self._stats["misses"] += 1
        return None

    async def set_decision(
        self,
        agent_id: str,
        tool_name: str,
        args_hash: str,
        decision: dict[str, Any],
    ) -> None:
        """Cache a firewall decision."""
        key = self._key("decision", agent_id, tool_name, args_hash)
        serialized = json.dumps(decision, default=str)
        try:
            if self._redis:
                await self._redis.set(key, serialized, ex=self._decision_ttl)
            else:
                self._local_set(key, decision, self._decision_ttl)
        except Exception:
            self._stats["errors"] += 1
            logger.debug("firewall_cache.set_decision_error", key=key)
            self._local_set(key, decision, self._decision_ttl)

    # ── Behavioral baseline cache ─────────────────────────────────

    async def get_baseline(self, agent_id: str) -> dict[str, Any] | None:
        """Get cached behavioral baseline for an agent."""
        key = self._key("baseline", agent_id)
        try:
            if self._redis:
                raw = await self._redis.get(key)
                if raw:
                    self._stats["hits"] += 1
                    return json.loads(raw)  # type: ignore[no-any-return]
            local = self._local_get(key)
            if local is not None:
                self._stats["hits"] += 1
                return local  # type: ignore[no-any-return]
        except Exception:
            self._stats["errors"] += 1
            logger.debug("firewall_cache.get_baseline_error", key=key)
            local = self._local_get(key)
            if local is not None:
                self._stats["hits"] += 1
                return local  # type: ignore[no-any-return]

        self._stats["misses"] += 1
        return None

    async def set_baseline(self, agent_id: str, baseline: dict[str, Any]) -> None:
        """Cache a behavioral baseline."""
        key = self._key("baseline", agent_id)
        serialized = json.dumps(baseline, default=str)
        try:
            if self._redis:
                await self._redis.set(key, serialized, ex=self._baseline_ttl)
            else:
                self._local_set(key, baseline, self._baseline_ttl)
        except Exception:
            self._stats["errors"] += 1
            logger.debug("firewall_cache.set_baseline_error", key=key)
            self._local_set(key, baseline, self._baseline_ttl)

    # ── Circuit breaker state ─────────────────────────────────────

    async def get_circuit_state(self, agent_id: str) -> str | None:
        """Get circuit breaker state: ``closed``, ``open``, or ``half_open``."""
        key = self._key("circuit", agent_id)
        try:
            if self._redis:
                raw = await self._redis.get(key)
                if raw:
                    self._stats["hits"] += 1
                    return raw if isinstance(raw, str) else raw.decode()
            local = self._local_get(key)
            if local is not None:
                self._stats["hits"] += 1
                return str(local)
        except Exception:
            self._stats["errors"] += 1
            logger.debug("firewall_cache.get_circuit_error", key=key)

        self._stats["misses"] += 1
        return None

    async def set_circuit_state(self, agent_id: str, state: str) -> None:
        """Set circuit breaker state."""
        if state not in ("closed", "open", "half_open"):
            raise ValueError(f"Invalid circuit state: {state}")

        key = self._key("circuit", agent_id)
        try:
            if self._redis:
                if self._circuit_ttl > 0:
                    await self._redis.set(key, state, ex=self._circuit_ttl)
                else:
                    await self._redis.set(key, state)
            else:
                self._local_set(key, state, self._circuit_ttl)
        except Exception:
            self._stats["errors"] += 1
            logger.debug("firewall_cache.set_circuit_error", key=key)
            self._local_set(key, state, self._circuit_ttl)

    # ── Rate limiting ─────────────────────────────────────────────

    async def increment_rate(self, agent_id: str) -> int:
        """Increment rate counter for the current minute window.

        Returns the current count after incrementing. Returns ``0`` if the
        counter cannot be updated (Redis unavailable, no local fallback for
        atomic increment).
        """
        minute = int(time.time() // 60)
        key = self._key("rate", agent_id, str(minute))
        try:
            if self._redis:
                count = await self._redis.incr(key)
                if count == 1:
                    await self._redis.expire(key, 120)  # 2-min TTL for safety
                return int(count)
        except Exception:
            self._stats["errors"] += 1
            logger.debug("firewall_cache.increment_rate_error", key=key)

        # Local fallback: approximate counter
        if key in self._local_cache:
            val, expiry = self._local_cache[key]
            if time.time() < expiry:
                new_count = int(val) + 1
                self._local_cache[key] = (new_count, expiry)
                self._stats["local_fallback"] += 1
                return new_count
        self._local_cache[key] = (1, time.time() + 120)
        self._stats["local_fallback"] += 1
        return 1

    async def get_rate(self, agent_id: str) -> int:
        """Get current rate count for this minute without incrementing."""
        minute = int(time.time() // 60)
        key = self._key("rate", agent_id, str(minute))
        try:
            if self._redis:
                raw = await self._redis.get(key)
                if raw:
                    return int(raw)
        except Exception:
            self._stats["errors"] += 1
        # Local fallback
        if key in self._local_cache:
            val, expiry = self._local_cache[key]
            if time.time() < expiry:
                return int(val)
        return 0

    # ── Bulk invalidation ─────────────────────────────────────────

    async def invalidate_agent(self, agent_id: str) -> int:
        """Invalidate all cached data for an agent (e.g. on kill-switch).

        Returns the number of keys deleted.
        """
        deleted = 0
        try:
            if self._redis:
                pattern = f"fw:*:{agent_id}:*"
                async for matched_key in self._redis.scan_iter(match=pattern):
                    await self._redis.delete(matched_key)
                    deleted += 1
                # Also delete direct agent keys (baseline, circuit)
                for sub in ("baseline", "circuit"):
                    key = self._key(sub, agent_id)
                    result = await self._redis.delete(key)
                    deleted += result
        except Exception:
            self._stats["errors"] += 1
            logger.warning("firewall_cache.invalidate_error", agent_id=agent_id)

        # Clear local cache entries for this agent
        local_keys = [
            k for k in self._local_cache if f":{agent_id}:" in k or k.endswith(f":{agent_id}")
        ]
        for k in local_keys:
            del self._local_cache[k]
            deleted += 1

        logger.info("firewall_cache.agent_invalidated", agent_id=agent_id, deleted=deleted)
        return deleted

    # ── Stats ─────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Return cache hit/miss statistics."""
        total = self._stats["hits"] + self._stats["misses"]
        return {
            **self._stats,
            "hit_rate_pct": round(self._stats["hits"] / max(total, 1) * 100, 2),
            "total_lookups": total,
            "local_cache_size": len(self._local_cache),
        }

    def reset_stats(self) -> None:
        """Reset all counters to zero."""
        self._stats = {"hits": 0, "misses": 0, "errors": 0, "local_fallback": 0}
