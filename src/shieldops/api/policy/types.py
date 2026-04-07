"""Public types for the request-policy engine.

All types here are pure data. The engine in :mod:`shieldops.api.policy.engine`
reads and writes them; adapters translate them at the boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Decision — sealed sum of evaluation results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    """Base class for :meth:`RequestPolicyEngine.evaluate` return values.

    Python does not have native sum types. Callers should use ``isinstance``
    or ``match`` to discriminate. The sum is closed to the four subclasses
    below — adding a new variant requires a deliberate RFC amendment so
    the ``PolicyMiddleware`` translator stays total.
    """


@dataclass(frozen=True)
class Allow(Decision):
    """The request may proceed."""


@dataclass(frozen=True)
class RateLimited(Decision):
    """The request was throttled. Maps to HTTP 429."""

    retry_after: float
    bucket: str


@dataclass(frozen=True)
class PlanExceeded(Decision):
    """The organisation's plan does not cover this request. Maps to HTTP 402."""

    reason: str
    plan: str


@dataclass(frozen=True)
class QuotaExceeded(Decision):
    """A named quota has been exceeded. Maps to HTTP 402.

    Quotas are "agents", "api_calls_per_month", "token_budget" — things
    that are different from rate limits (which are RPS/burst).
    """

    quota_name: str
    current: int
    limit: int


# ---------------------------------------------------------------------------
# Plan — what a tenant is entitled to
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Plan:
    """A tenant's plan. Loaded via :class:`PlanLoader`.

    ``rps`` and ``burst`` feed the token bucket. ``quotas`` is a dict
    of named counters (``{"agents": 10, "api_calls_per_month": 10_000}``)
    that the engine checks via :meth:`PlanLoader.get_usage`.
    """

    tier: str
    rps: float
    burst: int
    quotas: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# RequestCtx — what the middleware passes to evaluate()
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RequestCtx:
    """Everything the engine needs to make a decision.

    The route handler / middleware constructs this from the HTTP request;
    the engine itself is HTTP-agnostic.
    """

    org_id: str
    route_class: str
    """One of "default", "ingest", "query", "admin", or a quota name
    like "agents.create" that matches a key in :attr:`Plan.quotas`."""
    method: str = "GET"
    cost: int = 1
    """Token cost for the rate-limit bucket. Ingest = 1, heavy query = 10."""

    tier: str | None = None
    """If set, overrides the tier loaded from :class:`PlanLoader`."""

    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# OverrideTable — per-tenant "always allow" / "always deny" lists
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OverrideTable:
    """Per-tenant overrides that short-circuit the normal flow.

    ``always_allow`` bypasses all checks. ``always_deny`` rejects as
    ``PlanExceeded``. Kept intentionally small — plugins live outside
    this module in the :class:`PolicyDeps` frozen dataclass.
    """

    always_allow: frozenset[str] = field(default_factory=frozenset)
    always_deny: frozenset[str] = field(default_factory=frozenset)

    def is_always_allow(self, org_id: str) -> bool:
        return org_id in self.always_allow

    def is_always_deny(self, org_id: str) -> bool:
        return org_id in self.always_deny
