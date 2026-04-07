"""Per-tenant rate limit policy — TDD tests (#1).

TenantRateLimiter applies tier-specific bucket capacity per org_id.
"""

from __future__ import annotations

import pytest

from shieldops.api.middleware.tenant_rate_limiter import TenantRateLimiter


class TestTenantRateLimiterTiers:
    @pytest.mark.asyncio
    async def test_starter_tier_has_starter_limit(self) -> None:
        # Starter: 3 req capacity, 1 per second
        # Professional: 10 req capacity, 1 per second
        limiter = TenantRateLimiter(
            tier_capacities={
                "starter": (3, 1.0),
                "professional": (10, 1.0),
                "enterprise": (100, 1.0),
            },
            tier_for_org=lambda org: "starter",
        )
        # 3 should pass, 4th should be denied
        for _ in range(3):
            allowed, _ = await limiter.try_consume("org-a")
            assert allowed is True
        allowed, retry = await limiter.try_consume("org-a")
        assert allowed is False
        assert retry > 0

    @pytest.mark.asyncio
    async def test_professional_gets_higher_limit(self) -> None:
        limiter = TenantRateLimiter(
            tier_capacities={
                "starter": (3, 1.0),
                "professional": (10, 1.0),
            },
            tier_for_org=lambda org: "professional" if org == "pro-org" else "starter",
        )
        for _ in range(10):
            allowed, _ = await limiter.try_consume("pro-org")
            assert allowed is True
        allowed, _ = await limiter.try_consume("pro-org")
        assert allowed is False

    @pytest.mark.asyncio
    async def test_unknown_tier_falls_back_to_starter(self) -> None:
        limiter = TenantRateLimiter(
            tier_capacities={"starter": (2, 1.0), "professional": (10, 1.0)},
            tier_for_org=lambda org: "mystery_tier",
        )
        await limiter.try_consume("org-x")
        await limiter.try_consume("org-x")
        allowed, _ = await limiter.try_consume("org-x")
        assert allowed is False

    @pytest.mark.asyncio
    async def test_orgs_in_same_tier_have_independent_buckets(self) -> None:
        limiter = TenantRateLimiter(
            tier_capacities={"starter": (2, 1.0)},
            tier_for_org=lambda org: "starter",
        )
        await limiter.try_consume("org-a")
        await limiter.try_consume("org-a")
        assert (await limiter.try_consume("org-a"))[0] is False
        assert (await limiter.try_consume("org-b"))[0] is True
        assert (await limiter.try_consume("org-b"))[0] is True

    def test_constructor_requires_starter_tier(self) -> None:
        with pytest.raises(ValueError, match="starter"):
            TenantRateLimiter(
                tier_capacities={"professional": (10, 1.0)},
                tier_for_org=lambda org: "professional",
            )
