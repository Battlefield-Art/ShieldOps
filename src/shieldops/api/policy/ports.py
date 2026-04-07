"""Port Protocols for the request-policy engine core.

Every cross-boundary dependency the engine needs is expressed as a
Protocol here. Production wires real adapters at ``app.py`` lifespan;
tests wire in-memory adapters from :mod:`shieldops.api.policy.adapters`.

The engine core in :mod:`shieldops.api.policy.engine` has **zero imports**
from real SDKs — only from this module. Ruff rule ``SHOP-005`` will
enforce that once it lands.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from shieldops.api.policy.types import Plan


@runtime_checkable
class BucketStore(Protocol):
    """Token bucket state + atomicity. Redis-backed in production, deque-backed in tests."""

    async def take(
        self,
        key: str,
        capacity: int,
        refill_per_sec: float,
        cost: int,
        now: float,
    ) -> tuple[bool, float]:
        """Attempt to consume ``cost`` tokens from the bucket keyed by ``key``.

        Returns ``(allowed, retry_after_seconds)``.
        - ``allowed=True``: tokens were consumed. ``retry_after`` is 0.
        - ``allowed=False``: not enough tokens. ``retry_after`` is the
          number of seconds until the bucket has enough tokens for the
          requested ``cost``.

        Atomicity contract: concurrent callers with the same ``key``
        must not double-spend.
        """
        ...


@runtime_checkable
class PlanLoader(Protocol):
    """Loads plans and quota usage for tenants."""

    async def load(self, org_id: str) -> Plan:
        """Return the plan for ``org_id``. Never ``None`` — fallback to a
        default starter plan if the tenant is unknown."""
        ...

    async def get_usage(self, org_id: str, quota_name: str) -> int:
        """Return the current usage of a named quota for ``org_id``.
        Return 0 for unknown quotas."""
        ...


@runtime_checkable
class Clock(Protocol):
    """Injectable clock for deterministic rate-limit tests."""

    def now(self) -> float:
        """Return the current time as a Unix timestamp (seconds)."""
        ...


@runtime_checkable
class MetricsSink(Protocol):
    """Prometheus-compatible metrics sink."""

    def incr(self, name: str, **labels: str) -> None: ...
    def observe(self, name: str, value: float, **labels: str) -> None: ...


@runtime_checkable
class EventLog(Protocol):
    """Structured event log for audit trail."""

    def emit(self, event: str, **fields: Any) -> None: ...
