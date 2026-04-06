"""Redis-backed query result cache for the NL Query agent.

Caches the ``NLQueryResponse`` for a normalized question per tenant for a
short TTL (default 5 minutes). Falls back to an in-memory store when Redis
is unavailable — this keeps tests fast and avoids hard runtime dependencies.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any

import structlog

logger = structlog.get_logger()


_WHITESPACE = re.compile(r"\s+")

DEFAULT_TTL_SECONDS = 300
CACHE_NAMESPACE = "nlq"


def normalize_question(question: str) -> str:
    """Normalize a question for cache-key hashing.

    Lower-cases, strips punctuation-adjacent whitespace and collapses runs
    of whitespace so semantically identical queries hit the same cache key.
    """
    lowered = question.strip().lower()
    collapsed = _WHITESPACE.sub(" ", lowered)
    return collapsed


def build_cache_key(org_id: str, question: str) -> str:
    """Return the fully-qualified cache key for ``(org_id, question)``."""
    normalized = normalize_question(question)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"{CACHE_NAMESPACE}:{org_id}:{digest}"


class QueryCache:
    """Cache NL query results per-tenant with a short TTL.

    Parameters
    ----------
    redis_client:
        An async Redis client (``redis.asyncio.Redis``) or a compatible
        duck-typed object exposing ``get``/``set``/``delete``/``scan_iter``.
        When ``None``, an in-memory dict is used (useful for tests).
    default_ttl:
        Default TTL in seconds applied to ``set`` calls.
    """

    def __init__(
        self,
        redis_client: Any = None,
        default_ttl: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self._redis = redis_client
        self._default_ttl = default_ttl
        self._memory: dict[str, tuple[float, dict[str, Any]]] = {}
        self._hits = 0
        self._misses = 0

    # ── Serialization helpers ────────────────────────────────────

    @staticmethod
    def _dumps(value: dict[str, Any]) -> bytes:
        try:
            import orjson

            return orjson.dumps(value)
        except ImportError:
            import json

            return json.dumps(value, default=str).encode("utf-8")

    @staticmethod
    def _loads(raw: bytes | str) -> dict[str, Any]:
        try:
            import orjson

            return orjson.loads(raw)  # type: ignore[no-any-return]
        except ImportError:
            import json

            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            return json.loads(raw)  # type: ignore[no-any-return]

    # ── Core operations ──────────────────────────────────────────

    async def get(self, org_id: str, question: str) -> dict[str, Any] | None:
        """Return a cached result dict or ``None`` on miss."""
        key = build_cache_key(org_id, question)
        if self._redis is not None:
            try:
                raw = await self._redis.get(key)
                if raw is None:
                    self._misses += 1
                    return None
                self._hits += 1
                return self._loads(raw)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("nl_query.cache.get_failed", error=str(exc))
                return None

        # In-memory fallback
        entry = self._memory.get(key)
        if entry is None:
            self._misses += 1
            return None
        expires_at, value = entry
        if expires_at < time.monotonic():
            self._memory.pop(key, None)
            self._misses += 1
            return None
        self._hits += 1
        return value

    async def set(
        self,
        org_id: str,
        question: str,
        result: dict[str, Any],
        ttl: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        """Store a result dict under the tenant/question key."""
        key = build_cache_key(org_id, question)
        effective_ttl = ttl if ttl > 0 else self._default_ttl
        if self._redis is not None:
            try:
                await self._redis.set(key, self._dumps(result), ex=effective_ttl)
                return
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("nl_query.cache.set_failed", error=str(exc))
                return

        self._memory[key] = (time.monotonic() + effective_ttl, result)

    async def invalidate_org(self, org_id: str) -> int:
        """Invalidate all cached queries for an org. Returns count removed.

        Called when new data is ingested for the tenant (placeholder hook).
        """
        prefix = f"{CACHE_NAMESPACE}:{org_id}:"
        if self._redis is not None:
            deleted = 0
            try:
                async for key in self._redis.scan_iter(match=f"{prefix}*"):
                    await self._redis.delete(key)
                    deleted += 1
                logger.info(
                    "nl_query.cache.invalidated",
                    org_id=org_id,
                    deleted=deleted,
                )
                return deleted
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("nl_query.cache.invalidate_failed", error=str(exc))
                return deleted

        deleted = 0
        for key in list(self._memory.keys()):
            if key.startswith(prefix):
                self._memory.pop(key, None)
                deleted += 1
        return deleted

    def get_stats(self) -> dict[str, Any]:
        """Return basic hit/miss stats."""
        total = self._hits + self._misses
        ratio = (self._hits / total * 100) if total else 0.0
        return {
            "hits": self._hits,
            "misses": self._misses,
            "total": total,
            "hit_ratio_pct": round(ratio, 2),
        }
