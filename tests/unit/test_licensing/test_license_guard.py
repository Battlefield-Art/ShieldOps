"""License enforcement at agent startup — TDD tests (#2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from shieldops.licensing.guard import (
    LicenseExceededError,
    LicenseGuard,
)
from shieldops.licensing.models import License, LicenseTier


def _license(agent_limit: int, expires_days: int = 365) -> License:
    now = datetime.now(UTC)
    return License(
        org_id="test-org",
        tier=LicenseTier.PROFESSIONAL if agent_limit == 50 else LicenseTier.STARTER,
        agent_limit=agent_limit,
        issued_at=now,
        expires_at=now + timedelta(days=expires_days),
        signature="test-sig",
    )


class TestLicenseGuardAllow:
    def test_allows_starting_agent_under_limit(self) -> None:
        guard = LicenseGuard(license=_license(agent_limit=10))
        # 5 agents running, start a 6th → OK
        guard.current_agent_count = lambda: 5
        guard.check_can_start("investigation")  # should not raise

    def test_unlimited_tier_always_allows(self) -> None:
        guard = LicenseGuard(license=_license(agent_limit=-1))
        guard.current_agent_count = lambda: 10_000
        guard.check_can_start("any_agent")

    def test_allows_exactly_one_below_limit(self) -> None:
        guard = LicenseGuard(license=_license(agent_limit=10))
        guard.current_agent_count = lambda: 9
        guard.check_can_start("investigation")


class TestLicenseGuardDeny:
    def test_denies_starting_agent_at_limit(self) -> None:
        guard = LicenseGuard(license=_license(agent_limit=10))
        guard.current_agent_count = lambda: 10
        with pytest.raises(LicenseExceededError) as exc:
            guard.check_can_start("threat_hunter")
        assert exc.value.agent_name == "threat_hunter"
        assert exc.value.current == 10
        assert exc.value.limit == 10

    def test_denies_starting_agent_over_limit(self) -> None:
        """Safety net if count is already over (should never happen)."""
        guard = LicenseGuard(license=_license(agent_limit=5))
        guard.current_agent_count = lambda: 7
        with pytest.raises(LicenseExceededError):
            guard.check_can_start("soc_analyst")


class TestLicenseGuardExpiry:
    def test_denies_when_expired_past_grace(self) -> None:
        # Expired 60 days ago, grace is 30 → should deny
        guard = LicenseGuard(license=_license(agent_limit=10, expires_days=-60), grace_days=30)
        guard.current_agent_count = lambda: 0
        from shieldops.licensing.guard import LicenseExpiredError

        with pytest.raises(LicenseExpiredError, match="expired 60 days ago"):
            guard.check_can_start("investigation")

    def test_allows_within_grace_period(self) -> None:
        # Expired 10 days ago, grace is 30 → should allow
        guard = LicenseGuard(license=_license(agent_limit=10, expires_days=-10), grace_days=30)
        guard.current_agent_count = lambda: 5
        guard.check_can_start("investigation")
