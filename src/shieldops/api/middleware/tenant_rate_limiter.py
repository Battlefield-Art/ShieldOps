"""Per-tenant rate limit policy with tier-based bucket capacity.

Wraps the existing :class:`TokenBucket` so each tenant gets the bucket
appropriate for its subscription tier. The mapping is::

    tier_capacities = {
        "starter":      (5_000, 5_000 / 3600),    # 5K req/hour
        "professional": (50_000, 50_000 / 3600),  # 50K req/hour
        "enterprise":   (500_000, 500_000 / 3600),  # 500K req/hour
    }

A ``tier_for_org`` callback resolves an org_id → tier name. Unknown tiers
default to ``"starter"`` so a misconfigured/missing tier never permits
unlimited usage.
"""

from __future__ import annotations

from collections.abc import Callable

from shieldops.api.middleware.token_bucket import TokenBucket

DEFAULT_TIER = "starter"


class TenantRateLimiter:
    """Tier-based rate limiter — one TokenBucket per tier shared across orgs."""

    def __init__(
        self,
        *,
        tier_capacities: dict[str, tuple[int, float]],
        tier_for_org: Callable[[str], str],
    ) -> None:
        if DEFAULT_TIER not in tier_capacities:
            raise ValueError(f"tier_capacities must include the default tier '{DEFAULT_TIER}'")
        self._tier_for_org = tier_for_org
        self._buckets: dict[str, TokenBucket] = {
            tier: TokenBucket(capacity=cap, refill_rate_per_sec=rate)
            for tier, (cap, rate) in tier_capacities.items()
        }

    async def try_consume(self, org_id: str, tokens: int = 1) -> tuple[bool, float]:
        """Apply the org's tier-appropriate bucket. Returns (allowed, retry_after)."""
        tier = self._tier_for_org(org_id) or DEFAULT_TIER
        bucket = self._buckets.get(tier) or self._buckets[DEFAULT_TIER]
        return await bucket.try_consume(org_id, tokens=tokens)
