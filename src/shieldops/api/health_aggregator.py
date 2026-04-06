"""Deep health-check aggregator (#8).

Checks all critical dependencies in parallel with a per-check timeout and
caches results for a configurable TTL. The aggregator is intentionally
decoupled from specific providers — routes register :class:`HealthCheck`
instances at startup.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum

import structlog

logger = structlog.get_logger(__name__)


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


@dataclass
class CheckResult:
    name: str
    ok: bool
    message: str
    latency_ms: float


@dataclass
class AggregateResult:
    status: HealthStatus
    checks: dict[str, CheckResult] = field(default_factory=dict)
    cached: bool = False


@dataclass
class HealthCheck:
    name: str
    probe: Callable[[], Awaitable[tuple[bool, str]]]


class HealthAggregator:
    """Run a set of health checks in parallel with timeout + caching."""

    def __init__(
        self,
        checks: list[HealthCheck],
        *,
        cache_ttl_s: float = 5.0,
        per_check_timeout_s: float = 2.0,
    ) -> None:
        self._checks = checks
        self._cache_ttl_s = cache_ttl_s
        self._per_check_timeout_s = per_check_timeout_s
        self._cached_result: AggregateResult | None = None
        self._cached_at: float = 0.0
        self._lock = asyncio.Lock()

    async def check_all(self) -> AggregateResult:
        """Run all checks, using cached result if within TTL."""
        async with self._lock:
            now = time.monotonic()
            if (
                self._cached_result is not None
                and self._cache_ttl_s > 0
                and (now - self._cached_at) < self._cache_ttl_s
            ):
                cached = AggregateResult(
                    status=self._cached_result.status,
                    checks=self._cached_result.checks,
                    cached=True,
                )
                return cached

            results = await asyncio.gather(
                *(self._run_one(check) for check in self._checks),
                return_exceptions=False,
            )
            checks = {r.name: r for r in results}
            all_ok = all(r.ok for r in results)
            agg = AggregateResult(
                status=HealthStatus.HEALTHY if all_ok else HealthStatus.UNHEALTHY,
                checks=checks,
                cached=False,
            )
            self._cached_result = agg
            self._cached_at = now
            return agg

    async def _run_one(self, check: HealthCheck) -> CheckResult:
        start = time.monotonic()
        try:
            ok, message = await asyncio.wait_for(check.probe(), timeout=self._per_check_timeout_s)
        except TimeoutError:
            return CheckResult(
                name=check.name,
                ok=False,
                message=f"timeout after {self._per_check_timeout_s}s",
                latency_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return CheckResult(
                name=check.name,
                ok=False,
                message=f"error: {exc}",
                latency_ms=(time.monotonic() - start) * 1000,
            )
        return CheckResult(
            name=check.name,
            ok=ok,
            message=message,
            latency_ms=(time.monotonic() - start) * 1000,
        )
