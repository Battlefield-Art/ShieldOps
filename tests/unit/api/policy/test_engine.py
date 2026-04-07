"""Contract tests for RequestPolicyEngine — RFC #243 PR-1.

See ghantakiran/ShieldOps#243. The central test in this file is
:meth:`TestRateLimitContract.test_burst_then_refill_then_allow` — the
canonical rate-limit test. It publishes the sequence

    5 fast requests → 6th gets 429 with retry_after > 0 →
    clock.advance(1.0) → 7th succeeds

that every token-bucket implementation should pass. Before RFC #243
this test was impossible to write because there was no single place
where rate limit + billing + plan + clock could all be injected.

The other tests lock the other decision-order invariants:

- **Quota beats rate limit** — a quota-exceeded org gets 402 before
  the bucket is even consulted, so the metric is ``quota_exceeded``
  (not a noisy ``rate_limited``).
- **Override beats everything** — ``always_allow`` short-circuits the
  whole chain, providing a customer-support escape hatch.
- **``always_deny`` returns ``PlanExceeded``** without touching the
  buckets (no pressure from denylisted tenants).
- **Per-tenant isolation** — two orgs with different plans in the
  same engine do not share bucket state.
- **Metrics + events fire** — structured observations for every decision.

All tests use in-memory adapters — no Redis, no real time, no mocks.
Each runs in <5 ms.
"""

from __future__ import annotations

import pytest

from shieldops.api.policy import (
    Allow,
    Plan,
    PlanExceeded,
    PolicyDeps,
    QuotaExceeded,
    RateLimited,
    RequestCtx,
    RequestPolicyEngine,
    build_in_memory_engine,
    get_policy_engine,
    set_policy_engine,
    use_test_policy_engine,
)
from shieldops.api.policy.adapters import (
    CapturingEventLog,
    CapturingMetricsSink,
    InMemoryBucketStore,
    ManualClock,
    NullMetricsSink,
    StaticPlanLoader,
)
from shieldops.api.policy.types import OverrideTable

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _engine_with(
    *,
    plans: StaticPlanLoader | None = None,
    start_ts: float = 0.0,
    overrides: OverrideTable | None = None,
    capturing_metrics: bool = False,
    capturing_events: bool = True,
) -> tuple[RequestPolicyEngine, PolicyDeps]:
    """Assemble an engine with explicit test adapters."""
    deps = PolicyDeps(
        buckets=InMemoryBucketStore(),
        plans=plans or StaticPlanLoader(default=Plan(tier="starter", rps=10.0, burst=20)),
        clock=ManualClock(start=start_ts),
        metrics=CapturingMetricsSink() if capturing_metrics else NullMetricsSink(),
        events=CapturingEventLog() if capturing_events else _NoEvents(),
        overrides=overrides,
    )
    return RequestPolicyEngine(deps), deps


class _NoEvents:
    def emit(self, event: str, **fields: object) -> None:  # noqa: D401
        pass


# ---------------------------------------------------------------------------
# 1. THE CANONICAL RATE-LIMIT CONTRACT TEST
# ---------------------------------------------------------------------------


class TestRateLimitContract:
    """The one test this RFC exists to make possible."""

    @pytest.mark.asyncio
    async def test_burst_then_refill_then_allow(self) -> None:
        """5 fast requests succeed → 6th is 429 → after clock.advance(1.0) → 7th succeeds."""
        plans = StaticPlanLoader(
            default=Plan(tier="free", rps=1.0, burst=5)  # refill 1/s, burst 5
        )
        engine, deps = _engine_with(plans=plans, start_ts=1000.0)
        ctx = RequestCtx(org_id="org-a", route_class="default", method="GET")

        # Burst: 5 successive requests at t=1000.0 all succeed.
        for i in range(5):
            decision = await engine.evaluate(ctx)
            assert isinstance(decision, Allow), f"request {i + 1} should be allowed"

        # 6th request fails with a positive retry_after.
        decision = await engine.evaluate(ctx)
        assert isinstance(decision, RateLimited)
        assert decision.retry_after > 0
        assert decision.retry_after <= 1.0  # refill 1/s means ~1 s to recover 1 token

        # Advance the clock 1 second. The bucket refills by 1 token (rate=1.0).
        deps.clock.advance(1.0)  # type: ignore[attr-defined]

        # 7th request now succeeds.
        decision = await engine.evaluate(ctx)
        assert isinstance(decision, Allow)

    @pytest.mark.asyncio
    async def test_rate_limited_retry_after_scales_with_rate(self) -> None:
        """A slower refill rate gives a proportionally longer retry_after."""
        plans = StaticPlanLoader(default=Plan(tier="free", rps=0.5, burst=1))
        engine, _ = _engine_with(plans=plans)

        ctx = RequestCtx(org_id="org-a", route_class="default")
        assert isinstance(await engine.evaluate(ctx), Allow)
        decision = await engine.evaluate(ctx)
        assert isinstance(decision, RateLimited)
        # rate=0.5 → need 1 token → retry_after = 1 / 0.5 = 2.0s
        assert 1.9 <= decision.retry_after <= 2.1


# ---------------------------------------------------------------------------
# 2. Decision composition order: quota beats rate limit
# ---------------------------------------------------------------------------


class TestDecisionOrder:
    @pytest.mark.asyncio
    async def test_quota_exceeded_beats_rate_limit(self) -> None:
        """A quota-exceeded org gets 402 (QuotaExceeded), not 429 (RateLimited).

        This matters for dashboards + customer comms: "you're over
        your plan" is a billing signal, not a traffic signal.
        """
        plans = StaticPlanLoader(
            default=Plan(
                tier="free",
                rps=100.0,  # absurdly high RPS — rate limit should not bind
                burst=100,
                quotas={"agents": 10},
            )
        )
        plans.set_usage("org-a", "agents", 10)  # at the limit
        engine, _ = _engine_with(plans=plans)

        ctx = RequestCtx(org_id="org-a", route_class="agents.create")
        decision = await engine.evaluate(ctx)

        assert isinstance(decision, QuotaExceeded)
        assert decision.quota_name == "agents"
        assert decision.current == 10
        assert decision.limit == 10

    @pytest.mark.asyncio
    async def test_quota_under_limit_falls_through_to_rate_limit(self) -> None:
        """A quota under its limit is not blocked by the quota check —
        the normal rate limit path runs."""
        plans = StaticPlanLoader(default=Plan(tier="free", rps=1.0, burst=2, quotas={"agents": 10}))
        plans.set_usage("org-a", "agents", 5)  # under the limit
        engine, _ = _engine_with(plans=plans)

        ctx = RequestCtx(org_id="org-a", route_class="agents.create")
        # First two succeed (burst=2).
        assert isinstance(await engine.evaluate(ctx), Allow)
        assert isinstance(await engine.evaluate(ctx), Allow)
        # Third is rate-limited, not quota-exceeded.
        decision = await engine.evaluate(ctx)
        assert isinstance(decision, RateLimited)

    @pytest.mark.asyncio
    async def test_exact_quota_match_short_circuits(self) -> None:
        """route_class == quota_name works as well as route_class.startswith."""
        plans = StaticPlanLoader(
            default=Plan(tier="free", rps=100.0, burst=100, quotas={"admin_ops": 5})
        )
        plans.set_usage("org-a", "admin_ops", 5)
        engine, _ = _engine_with(plans=plans)

        ctx = RequestCtx(org_id="org-a", route_class="admin_ops")
        decision = await engine.evaluate(ctx)
        assert isinstance(decision, QuotaExceeded)


# ---------------------------------------------------------------------------
# 3. Overrides
# ---------------------------------------------------------------------------


class TestOverrides:
    @pytest.mark.asyncio
    async def test_always_allow_short_circuits_everything(self) -> None:
        """A tenant on the always_allow list bypasses rate + quota + plan."""
        plans = StaticPlanLoader(default=Plan(tier="free", rps=0.0, burst=0, quotas={"agents": 0}))
        plans.set_usage("vip", "agents", 999)
        overrides = OverrideTable(always_allow=frozenset({"vip"}))
        engine, _ = _engine_with(plans=plans, overrides=overrides)

        ctx = RequestCtx(org_id="vip", route_class="agents.create")
        # Even with burst=0 and quota exhausted, vip passes.
        for _ in range(100):
            assert isinstance(await engine.evaluate(ctx), Allow)

    @pytest.mark.asyncio
    async def test_always_deny_returns_plan_exceeded(self) -> None:
        overrides = OverrideTable(always_deny=frozenset({"banned"}))
        engine, _ = _engine_with(overrides=overrides)

        ctx = RequestCtx(org_id="banned", route_class="default")
        decision = await engine.evaluate(ctx)
        assert isinstance(decision, PlanExceeded)
        assert "deny" in decision.reason.lower()

    @pytest.mark.asyncio
    async def test_always_deny_does_not_consume_bucket(self) -> None:
        """A denied request must not increment the bucket pressure."""
        store = InMemoryBucketStore()
        deps = PolicyDeps(
            buckets=store,
            plans=StaticPlanLoader(default=Plan(tier="free", rps=1.0, burst=5)),
            clock=ManualClock(),
            metrics=NullMetricsSink(),
            events=CapturingEventLog(),
            overrides=OverrideTable(always_deny=frozenset({"banned"})),
        )
        engine = RequestPolicyEngine(deps)
        ctx = RequestCtx(org_id="banned", route_class="default")

        for _ in range(10):
            await engine.evaluate(ctx)

        # Bucket was never touched.
        assert store.current_tokens("banned:default") is None


# ---------------------------------------------------------------------------
# 4. Per-tenant isolation
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    @pytest.mark.asyncio
    async def test_two_tenants_have_independent_buckets(self) -> None:
        plans = StaticPlanLoader(default=Plan(tier="free", rps=1.0, burst=2))
        engine, _ = _engine_with(plans=plans)

        ctx_a = RequestCtx(org_id="org-a", route_class="default")
        ctx_b = RequestCtx(org_id="org-b", route_class="default")

        # org-a burns through its burst.
        assert isinstance(await engine.evaluate(ctx_a), Allow)
        assert isinstance(await engine.evaluate(ctx_a), Allow)
        assert isinstance(await engine.evaluate(ctx_a), RateLimited)

        # org-b is untouched — its bucket is full.
        assert isinstance(await engine.evaluate(ctx_b), Allow)
        assert isinstance(await engine.evaluate(ctx_b), Allow)
        assert isinstance(await engine.evaluate(ctx_b), RateLimited)

    @pytest.mark.asyncio
    async def test_two_route_classes_on_same_tenant_are_isolated(self) -> None:
        """``ingest`` and ``query`` on the same tenant have separate buckets."""
        plans = StaticPlanLoader(default=Plan(tier="free", rps=1.0, burst=1))
        engine, _ = _engine_with(plans=plans)

        ingest = RequestCtx(org_id="org-a", route_class="ingest")
        query = RequestCtx(org_id="org-a", route_class="query")

        assert isinstance(await engine.evaluate(ingest), Allow)
        assert isinstance(await engine.evaluate(ingest), RateLimited)
        # Query bucket is still full.
        assert isinstance(await engine.evaluate(query), Allow)


# ---------------------------------------------------------------------------
# 5. Metrics + events
# ---------------------------------------------------------------------------


class TestObservability:
    @pytest.mark.asyncio
    async def test_allow_emits_policy_allow_metric(self) -> None:
        engine, deps = _engine_with(capturing_metrics=True)
        ctx = RequestCtx(org_id="org-a", route_class="default")
        await engine.evaluate(ctx)

        metrics = deps.metrics  # type: ignore[assignment]
        assert metrics.count_where("policy.allow") >= 1  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_rate_limited_emits_policy_rate_limited_event(self) -> None:
        plans = StaticPlanLoader(default=Plan(tier="free", rps=1.0, burst=1))
        engine, deps = _engine_with(plans=plans)
        ctx = RequestCtx(org_id="org-a", route_class="default")

        await engine.evaluate(ctx)  # allowed
        await engine.evaluate(ctx)  # rate-limited

        events = deps.events  # type: ignore[assignment]
        assert events.count_where("policy.rate_limited", org_id="org-a") >= 1  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_quota_exceeded_emits_policy_quota_exceeded_event(self) -> None:
        plans = StaticPlanLoader(
            default=Plan(tier="free", rps=100.0, burst=100, quotas={"agents": 1})
        )
        plans.set_usage("org-a", "agents", 1)
        engine, deps = _engine_with(plans=plans)
        ctx = RequestCtx(org_id="org-a", route_class="agents.create")

        await engine.evaluate(ctx)

        events = deps.events  # type: ignore[assignment]
        assert events.count_where("policy.quota_exceeded", quota_name="agents") >= 1  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# 6. Composition root + use_test_policy_engine
# ---------------------------------------------------------------------------


class TestComposition:
    def test_get_engine_raises_when_not_installed(self) -> None:
        set_policy_engine(None)
        with pytest.raises(RuntimeError, match="No RequestPolicyEngine installed"):
            get_policy_engine()

    def test_use_test_engine_installs_and_restores(self) -> None:
        original, _ = build_in_memory_engine()
        set_policy_engine(original)

        with use_test_policy_engine() as fresh:
            assert get_policy_engine() is fresh
            assert fresh is not original

        assert get_policy_engine() is original
        set_policy_engine(None)

    def test_use_test_engine_restores_on_exception(self) -> None:
        original, _ = build_in_memory_engine()
        set_policy_engine(original)

        with pytest.raises(ValueError, match="test failure"), use_test_policy_engine():
            raise ValueError("test failure")

        assert get_policy_engine() is original
        set_policy_engine(None)
