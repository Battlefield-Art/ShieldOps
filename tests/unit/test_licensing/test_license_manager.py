"""Contract tests for LicenseManager + @enforced + use_test_license.

See RFC #244 (ghantakiran/ShieldOps#244). These tests lock the structural
invariants PR-1 introduces:

1. **Lease is leak-free by construction** — an exception mid-run still
   decrements the running count. This is the subtlest invariant and the
   reason :class:`AgentLease` exists as a context manager rather than a
   pair of notify_started/notify_stopped functions.

2. **Multi-tenant is trivial** — constructing two managers with
   different ``license.org_id`` values gives fully isolated state. No
   module-level globals are touched by the manager itself.

3. **`@enforced` auto-applies** — a runner decorated with
   ``@enforced("x")`` has the license check and the lease release
   wired without the author writing ``try/finally``.

4. **``use_test_license`` restores the previous manager** even on
   exception — the Phase-1 test seam that replaces the old
   ``set_guard(None)`` / ``reset_global_tracker()`` ceremony.

All tests run against in-process ``LicenseManager`` instances. No file
I/O, no globals (the test-seam context manager manages the composition
root locally), no monkey-patching.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta

import pytest

from shieldops.licensing import License, LicenseTier
from shieldops.licensing.composition import (
    get_license_manager,
    set_license_manager,
    use_test_license,
)
from shieldops.licensing.enforce import enforce, enforced
from shieldops.licensing.manager import (
    AgentLease,
    LicenseExpiredError,
    LicenseLimitError,
    LicenseManager,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_license(
    *,
    org_id: str = "org-a",
    tier: str = "starter",
    agent_limit: int = 2,
    issued: datetime | None = None,
    expires: datetime | None = None,
) -> License:
    now = datetime.now(UTC)
    return License(
        org_id=org_id,
        tier=tier,
        agent_limit=agent_limit,
        issued_at=issued or now,
        expires_at=expires or (now + timedelta(days=365)),
        signature="test-sig",
    )


@pytest.fixture(autouse=True)
def _isolate_composition_root():
    """Every test starts with no manager installed, ends the same way."""
    previous = None
    with contextlib.suppress(RuntimeError):
        previous = get_license_manager()
    set_license_manager(None)
    yield
    set_license_manager(previous)


# ---------------------------------------------------------------------------
# 1. THE LEASE INVARIANT — exception mid-run does not leak a slot
# ---------------------------------------------------------------------------


class TestLeaseIsLeakFree:
    """The single subtlest invariant. Without this, @enforced is unsafe."""

    def test_exception_during_run_releases_the_slot(self) -> None:
        mgr = LicenseManager(license=_make_license(agent_limit=1))

        assert mgr.running_count == 0
        with pytest.raises(ValueError, match="boom"), mgr.admit("agent-a"):
            assert mgr.running_count == 1
            raise ValueError("boom")
        # The exception unwound through the context manager — the slot
        # MUST be released. This is the whole point of the lease pattern.
        assert mgr.running_count == 0

        # And a fresh agent can still be admitted after the crash.
        with mgr.admit("agent-b"):
            assert mgr.running_count == 1

    def test_clean_exit_releases_the_slot(self) -> None:
        mgr = LicenseManager(license=_make_license(agent_limit=1))
        with mgr.admit("agent-a"):
            assert mgr.running_count == 1
        assert mgr.running_count == 0

    def test_lease_release_is_idempotent(self) -> None:
        mgr = LicenseManager(license=_make_license(agent_limit=1))
        lease = mgr.admit("agent-a")
        assert mgr.running_count == 1
        lease.release()
        lease.release()  # safe
        lease.release()
        assert mgr.running_count == 0

    @pytest.mark.asyncio
    async def test_async_lease_exception_releases_the_slot(self) -> None:
        mgr = LicenseManager(license=_make_license(agent_limit=1))
        with pytest.raises(ValueError, match="async boom"):
            async with mgr.admit("agent-a"):
                assert mgr.running_count == 1
                raise ValueError("async boom")
        assert mgr.running_count == 0


# ---------------------------------------------------------------------------
# 2. Limit enforcement
# ---------------------------------------------------------------------------


class TestLimitEnforcement:
    def test_admit_blocks_at_limit(self) -> None:
        mgr = LicenseManager(license=_make_license(agent_limit=2))

        lease_a = mgr.admit("a")
        lease_b = mgr.admit("b")
        with pytest.raises(LicenseLimitError) as exc_info:
            mgr.admit("c")
        assert exc_info.value.agent_name == "c"
        assert exc_info.value.current == 2
        assert exc_info.value.limit == 2

        lease_a.release()
        # Now c can fit.
        with mgr.admit("c"):
            assert mgr.running_count == 2
        lease_b.release()
        assert mgr.running_count == 0

    def test_unlimited_tier_never_blocks(self) -> None:
        mgr = LicenseManager.unlimited()
        leases = [mgr.admit(f"agent-{i}") for i in range(100)]
        assert mgr.running_count == 100
        for lease in leases:
            lease.release()
        assert mgr.running_count == 0

    def test_re_admitting_same_agent_name_is_idempotent(self) -> None:
        """An agent that's already in the running set doesn't consume a new slot."""
        mgr = LicenseManager(license=_make_license(agent_limit=1))
        # Same name admitted twice — doesn't hit the limit because it's
        # already in the running set.
        with mgr.admit("a"), mgr.admit("a"):
            assert mgr.running_count == 1


# ---------------------------------------------------------------------------
# 3. Expiry + grace period
# ---------------------------------------------------------------------------


class TestExpiry:
    def test_license_past_grace_raises_expired(self) -> None:
        now = datetime.now(UTC)
        license = _make_license(
            expires=now - timedelta(days=40),  # 40 days past expiry
        )
        mgr = LicenseManager(license=license, grace_days=30)
        with pytest.raises(LicenseExpiredError) as exc_info:
            mgr.admit("a")
        assert exc_info.value.grace_days == 30
        assert exc_info.value.days_past_grace == 40

    def test_license_within_grace_is_admitted(self) -> None:
        now = datetime.now(UTC)
        license = _make_license(expires=now - timedelta(days=5))
        mgr = LicenseManager(license=license, grace_days=30)
        with mgr.admit("a"):
            assert mgr.running_count == 1

    def test_clock_injection_controls_time(self) -> None:
        """Tests should not depend on wall-clock time."""
        frozen = datetime(2026, 6, 1, tzinfo=UTC)
        license = _make_license(
            expires=datetime(2026, 1, 1, tzinfo=UTC),  # expired 151 days ago
        )
        mgr = LicenseManager(license=license, grace_days=30, clock=lambda: frozen)
        with pytest.raises(LicenseExpiredError):
            mgr.admit("a")


# ---------------------------------------------------------------------------
# 4. Multi-tenant isolation
# ---------------------------------------------------------------------------


class TestMultiTenant:
    def test_two_managers_are_fully_isolated(self) -> None:
        mgr_a = LicenseManager(license=_make_license(org_id="acme", agent_limit=1))
        mgr_b = LicenseManager(license=_make_license(org_id="globex", agent_limit=1))

        with mgr_a.admit("a"):
            # mgr_a is at limit but mgr_b is free.
            with mgr_b.admit("a"):
                assert mgr_a.running_count == 1
                assert mgr_b.running_count == 1
            assert mgr_b.running_count == 0
            assert mgr_a.running_count == 1

        assert mgr_a.running_count == 0
        assert mgr_b.running_count == 0


# ---------------------------------------------------------------------------
# 5. @enforced decorator
# ---------------------------------------------------------------------------


class TestEnforcedDecorator:
    def test_sync_runner_gets_enforcement(self) -> None:
        class ThreatHunter:
            @enforced("threat_hunter")
            def run(self, x: int) -> int:
                return x * 2

        with use_test_license(LicenseManager(license=_make_license(agent_limit=1))) as mgr:
            hunter = ThreatHunter()
            assert hunter.run(5) == 10
            # Slot was released after the run.
            assert mgr.running_count == 0

    @pytest.mark.asyncio
    async def test_async_runner_gets_enforcement(self) -> None:
        class InvestigationRunner:
            @enforced("investigation")
            async def run(self, x: int) -> int:
                return x + 1

        with use_test_license() as mgr:
            runner = InvestigationRunner()
            assert await runner.run(41) == 42
            assert mgr.running_count == 0

    def test_enforced_raises_limit_error_when_full(self) -> None:
        class Runner:
            @enforced("agent-x")
            def run(self) -> None:
                pass

        other_license_holder = LicenseManager(license=_make_license(agent_limit=1))
        # Pre-fill the slot with a different agent name so "agent-x" can't fit.
        lease = other_license_holder.admit("other")
        try:
            with use_test_license(other_license_holder):
                runner = Runner()
                with pytest.raises(LicenseLimitError):
                    runner.run()
        finally:
            lease.release()

    def test_enforced_exception_releases_slot(self) -> None:
        """The single most important test — @enforced must not leak slots."""

        class Runner:
            @enforced("crashy")
            def run(self) -> None:
                raise RuntimeError("boom")

        with use_test_license() as mgr:
            runner = Runner()
            with pytest.raises(RuntimeError, match="boom"):
                runner.run()
            assert mgr.running_count == 0

    def test_double_decoration_is_noop(self) -> None:
        """The _shieldops_enforced marker makes re-application safe."""
        call_counts = {"outer": 0, "inner": 0}

        @enforced("agent-x")
        def run() -> None:
            call_counts["inner"] += 1

        # Re-apply the decorator — this simulates the codemod hitting an
        # already-decorated runner, or the framework wrapper running after
        # an explicit @enforced.
        double = enforced("agent-x")(run)
        assert double is run  # same function object, not a re-wrap

        with use_test_license() as mgr:
            run()
            assert call_counts["inner"] == 1
            assert mgr.running_count == 0


# ---------------------------------------------------------------------------
# 6. enforce() async context manager
# ---------------------------------------------------------------------------


class TestEnforceContextManager:
    @pytest.mark.asyncio
    async def test_enforce_admits_and_releases(self) -> None:
        with use_test_license() as mgr:
            async with enforce("my-agent") as lease:
                assert isinstance(lease, AgentLease)
                assert mgr.running_count == 1
            assert mgr.running_count == 0

    @pytest.mark.asyncio
    async def test_enforce_exception_releases_slot(self) -> None:
        with use_test_license() as mgr:
            with pytest.raises(ValueError, match="oops"):
                async with enforce("my-agent"):
                    raise ValueError("oops")
            assert mgr.running_count == 0


# ---------------------------------------------------------------------------
# 7. use_test_license — the test seam
# ---------------------------------------------------------------------------


class TestUseTestLicense:
    def test_restores_previous_manager_on_clean_exit(self) -> None:
        original = LicenseManager.unlimited(org_id="original")
        set_license_manager(original)

        with use_test_license() as mgr:
            assert get_license_manager() is mgr
            assert mgr is not original

        assert get_license_manager() is original

    def test_restores_previous_manager_on_exception(self) -> None:
        original = LicenseManager.unlimited(org_id="original")
        set_license_manager(original)

        with pytest.raises(ValueError, match="test failure"), use_test_license():
            raise ValueError("test failure")

        # The previous manager is restored even though the block raised.
        assert get_license_manager() is original

    def test_restores_none_when_no_previous_manager(self) -> None:
        set_license_manager(None)
        with use_test_license() as mgr:
            assert get_license_manager() is mgr
        with pytest.raises(RuntimeError, match="No LicenseManager installed"):
            get_license_manager()

    def test_pass_custom_manager(self) -> None:
        custom = LicenseManager(license=_make_license(agent_limit=7))
        with use_test_license(custom) as mgr:
            assert mgr is custom
            assert mgr.license.agent_limit == 7


# ---------------------------------------------------------------------------
# 8. No module-level globals — smoke test
# ---------------------------------------------------------------------------


class TestNoModuleGlobals:
    def test_two_manager_instances_do_not_share_state(self) -> None:
        mgr1 = LicenseManager(license=_make_license(agent_limit=1))
        mgr2 = LicenseManager(license=_make_license(agent_limit=1))
        with mgr1.admit("a"), mgr2.admit("a"):  # would fail if they shared state
            assert mgr1.running_count == 1
            assert mgr2.running_count == 1

    def test_license_tier_enum_still_exported(self) -> None:
        """Smoke test that the existing __init__.py exports still work."""
        # LicenseTier is imported from __init__; should not have broken.
        assert LicenseTier.STARTER == "starter"
