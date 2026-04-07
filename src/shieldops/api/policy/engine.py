"""The RequestPolicyEngine core — pure logic over injected ports.

This is the deep module that replaces the dual stack builders +
three rate-limit implementations + two billing enforcement modules
scattered across ``src/shieldops/api/middleware/`` today.

The engine answers ONE question::

    decision = await engine.evaluate(ctx)

where ``decision`` is one of :class:`Allow`, :class:`RateLimited`,
:class:`PlanExceeded`, or :class:`QuotaExceeded`. A thin
``PolicyMiddleware`` (landing in PR-3) translates the decision to an
HTTP response (200 / 429 / 402).

Decision composition order (locked by contract tests):

    override_always_allow → override_always_deny → quota → rate_limit → allow

Rationale:
- ``override_always_allow`` must bypass everything — customer-support
  escape hatch for in-flight incidents.
- ``override_always_deny`` returns :class:`PlanExceeded` without
  touching the buckets — no bucket pressure from denylisted tenants.
- ``quota`` beats ``rate_limit`` so a quota-exceeded org gets HTTP 402
  (payment required) rather than a noisy HTTP 429. The distinction
  matters for dashboards + customer communication.
- ``rate_limit`` is the final gate.

The engine has **zero imports** from ``redis``, ``time``, ``structlog``,
``opentelemetry``, ``fastapi``, ``starlette``. Only from ``types``,
``ports``, and ``deps``. Lint rule ``SHOP-005`` will enforce this.
"""

from __future__ import annotations

from shieldops.api.policy.deps import PolicyDeps
from shieldops.api.policy.types import (
    Allow,
    Decision,
    PlanExceeded,
    QuotaExceeded,
    RateLimited,
    RequestCtx,
)


class RequestPolicyEngine:
    """Pure-ish policy engine. Depends only on the injected ports in :class:`PolicyDeps`."""

    def __init__(self, deps: PolicyDeps) -> None:
        self._deps = deps

    async def evaluate(self, ctx: RequestCtx) -> Decision:
        """Evaluate the request and return a :class:`Decision`.

        The body is deliberately small and sequential so the decision
        composition order is readable in one place.
        """
        deps = self._deps

        # ---- STEP 1: overrides ----------------------------------------
        if deps.overrides is not None:
            if deps.overrides.is_always_allow(ctx.org_id):
                deps.events.emit(
                    "policy.allow.override",
                    org_id=ctx.org_id,
                    route_class=ctx.route_class,
                )
                deps.metrics.incr("policy.allow", reason="override")
                return Allow()
            if deps.overrides.is_always_deny(ctx.org_id):
                deps.events.emit(
                    "policy.deny.override",
                    org_id=ctx.org_id,
                    route_class=ctx.route_class,
                )
                deps.metrics.incr("policy.deny", reason="override")
                return PlanExceeded(reason="tenant on deny list", plan="override")

        # ---- STEP 2: load plan ----------------------------------------
        plan = await deps.plans.load(ctx.org_id)

        # ---- STEP 3: quota check (before rate limit) ------------------
        # If the route class is one of the plan's named quotas (e.g.
        # "agents.create" matches "agents"), check the usage counter.
        quota_name = _quota_key_for(ctx.route_class, plan)
        if quota_name is not None:
            current = await deps.plans.get_usage(ctx.org_id, quota_name)
            limit = plan.quotas[quota_name]
            if current >= limit:
                deps.events.emit(
                    "policy.quota_exceeded",
                    org_id=ctx.org_id,
                    quota_name=quota_name,
                    current=current,
                    limit=limit,
                )
                deps.metrics.incr(
                    "policy.quota_exceeded",
                    org_id=ctx.org_id,
                    quota_name=quota_name,
                )
                return QuotaExceeded(quota_name=quota_name, current=current, limit=limit)

        # ---- STEP 4: rate limit via token bucket ----------------------
        bucket_key = f"{ctx.org_id}:{ctx.route_class}"
        now = deps.clock.now()
        allowed, retry_after = await deps.buckets.take(
            key=bucket_key,
            capacity=plan.burst,
            refill_per_sec=plan.rps,
            cost=ctx.cost,
            now=now,
        )
        if not allowed:
            deps.events.emit(
                "policy.rate_limited",
                org_id=ctx.org_id,
                route_class=ctx.route_class,
                retry_after=retry_after,
            )
            deps.metrics.incr(
                "policy.rate_limited",
                org_id=ctx.org_id,
                route_class=ctx.route_class,
            )
            deps.metrics.observe(
                "policy.retry_after_seconds",
                retry_after,
                route_class=ctx.route_class,
            )
            return RateLimited(retry_after=retry_after, bucket=bucket_key)

        # ---- STEP 5: all checks passed --------------------------------
        deps.events.emit(
            "policy.allow",
            org_id=ctx.org_id,
            route_class=ctx.route_class,
        )
        deps.metrics.incr("policy.allow", org_id=ctx.org_id)
        return Allow()


def _quota_key_for(route_class: str, plan: Plan) -> str | None:  # noqa: F821
    """Map a route_class to a quota key if one applies.

    Simple matching rule: a route_class matches a quota if it equals
    the quota name OR starts with ``quota_name + "."``. E.g. route_class
    ``"agents.create"`` matches quota ``"agents"``.
    """
    for name in plan.quotas:
        if route_class == name or route_class.startswith(f"{name}."):
            return name
    return None


# Late import to satisfy the type comment above without a circular import.
from shieldops.api.policy.types import Plan  # noqa: E402
