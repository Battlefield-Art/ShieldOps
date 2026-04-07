"""Request-policy engine — rate limit + billing enforcement in one place.

See RFC #243 (ghantakiran/ShieldOps#243). This package replaces the
24-file / 3,002-LOC middleware sprawl with a pure :class:`RequestPolicyEngine`
core that answers a single question: ``evaluate(ctx) -> Decision``.

PR-1 scope:
- Core engine + 5 port Protocols
- In-memory adapters for <10ms contract tests
- The canonical burst→refill rate-limit test
- The canonical quota-before-rate-limit decision-order test

PR-2 adds production adapters (Redis bucket store, DB plan loader,
Prometheus metrics, structlog events). PR-3 installs :class:`PolicyMiddleware`
in **shadow mode** alongside the existing stack. PR-4 flips to enforce
and deletes the 24-file middleware sprawl.
"""

from __future__ import annotations

from shieldops.api.policy.composition import (
    build_in_memory_engine,
    get_policy_engine,
    set_policy_engine,
    use_test_policy_engine,
)
from shieldops.api.policy.deps import PolicyDeps
from shieldops.api.policy.engine import RequestPolicyEngine
from shieldops.api.policy.ports import (
    BucketStore,
    Clock,
    EventLog,
    MetricsSink,
    PlanLoader,
)
from shieldops.api.policy.types import (
    Allow,
    Decision,
    Plan,
    PlanExceeded,
    QuotaExceeded,
    RateLimited,
    RequestCtx,
)

__all__ = [
    "Allow",
    "BucketStore",
    "Clock",
    "Decision",
    "EventLog",
    "MetricsSink",
    "Plan",
    "PlanExceeded",
    "PlanLoader",
    "PolicyDeps",
    "QuotaExceeded",
    "RateLimited",
    "RequestCtx",
    "RequestPolicyEngine",
    "build_in_memory_engine",
    "get_policy_engine",
    "set_policy_engine",
    "use_test_policy_engine",
]
