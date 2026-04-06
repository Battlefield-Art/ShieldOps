"""License startup hook — integration with agent runners (TDD #2-wire)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from shieldops.licensing import startup_hook
from shieldops.licensing.guard import (
    LicenseExceededError,
    LicenseExpiredError,
    LicenseGuard,
)
from shieldops.licensing.models import License, LicenseTier


def _license(agent_limit: int, expires_days: int = 365) -> License:
    now = datetime.now(UTC)
    return License(
        org_id="test-org",
        tier=LicenseTier.PROFESSIONAL,
        agent_limit=agent_limit,
        issued_at=now,
        expires_at=now + timedelta(days=expires_days),
        signature="sig",
    )


@pytest.fixture(autouse=True)
def reset_guard() -> None:
    startup_hook.set_guard(None)
    yield
    startup_hook.set_guard(None)


class TestStartupHook:
    def test_no_guard_allows_startup(self) -> None:
        """When no guard is installed, agents start freely (dev mode)."""
        startup_hook.check_startup("investigation")  # should not raise

    def test_guard_allows_under_limit(self) -> None:
        guard = LicenseGuard(license=_license(agent_limit=10))
        guard.current_agent_count = lambda: 5
        startup_hook.set_guard(guard)
        startup_hook.check_startup("investigation")

    def test_guard_denies_at_limit(self) -> None:
        guard = LicenseGuard(license=_license(agent_limit=3))
        guard.current_agent_count = lambda: 3
        startup_hook.set_guard(guard)
        with pytest.raises(LicenseExceededError):
            startup_hook.check_startup("threat_hunter")

    def test_guard_denies_expired_past_grace(self) -> None:
        guard = LicenseGuard(license=_license(agent_limit=100, expires_days=-60), grace_days=30)
        guard.current_agent_count = lambda: 0
        startup_hook.set_guard(guard)
        with pytest.raises(LicenseExpiredError):
            startup_hook.check_startup("investigation")

    def test_counter_increments_on_successful_startup(self) -> None:
        """The hook should track running-agent count so guard sees accurate state."""
        guard = LicenseGuard(license=_license(agent_limit=2))
        # Bind the guard's counter to the hook's internal counter
        guard.current_agent_count = startup_hook.get_running_count
        startup_hook.set_guard(guard)
        startup_hook.reset_running_count()

        startup_hook.check_startup("a")
        startup_hook.notify_started("a")
        startup_hook.check_startup("b")
        startup_hook.notify_started("b")

        # Third agent should fail
        with pytest.raises(LicenseExceededError):
            startup_hook.check_startup("c")

    def test_notify_stopped_frees_slot(self) -> None:
        guard = LicenseGuard(license=_license(agent_limit=2))
        guard.current_agent_count = startup_hook.get_running_count
        startup_hook.set_guard(guard)
        startup_hook.reset_running_count()

        startup_hook.check_startup("a")
        startup_hook.notify_started("a")
        startup_hook.check_startup("b")
        startup_hook.notify_started("b")
        # Stop one
        startup_hook.notify_stopped("a")
        # Now can start a new one
        startup_hook.check_startup("c")
        startup_hook.notify_started("c")
        assert startup_hook.get_running_count() == 2
