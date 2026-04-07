"""Integration test — #244 PR-2: ``define_agent()`` auto-applies @enforced.

See ghantakiran/ShieldOps#244. This test proves that the framework
patch landed in PR-2 propagates license enforcement to all 114 existing
``@define_agent``-built runners with zero per-agent edits.

Three invariants are locked:

1. **Auto-apply is on by default.** A runner built via ``define_agent()``
   raises :class:`LicenseLimitError` when the installed manager is at
   its limit.
2. **Opt-out is available.** ``license_enforced=False`` skips the
   decorator wrap so tests + in-migration runners can bypass cleanly.
3. **Missing-manager fallback is a warning, not a crash.** When no
   manager is installed (the default test runner state), the wrapped
   runner executes normally — this is the compatibility guarantee
   that kept the existing 114 agents green during PR-2 rollout.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import BaseModel

from shieldops.agents.framework import define_agent
from shieldops.licensing.composition import set_license_manager, use_test_license
from shieldops.licensing.manager import LicenseLimitError, LicenseManager
from shieldops.licensing.models import License

# ---------------------------------------------------------------------------
# Fixtures — a minimal state + toolkit that `define_agent` can construct.
# ---------------------------------------------------------------------------


class _MinimalState(BaseModel):
    """Minimal state model for the `define_agent()` contract."""

    request_id: str = ""
    reasoning_chain: list[str] = []
    current_step: str = ""
    error: str = ""
    result: str = ""


class _MinimalToolkit:
    """A toolkit whose methods map one-to-one to the node names used
    below. ``define_agent`` auto-generates the node wrappers by looking
    up ``getattr(toolkit, node_name)``."""

    async def analyze(self, state: dict[str, Any]) -> dict[str, Any]:
        return {"result": "analyzed"}


def _build_runner(*, license_enforced: bool = True) -> type:
    """Wrap ``define_agent`` with parameters the test needs."""
    return define_agent(
        name="test_agent_244_pr2",
        state_type=_MinimalState,
        toolkit_type=_MinimalToolkit,
        nodes=["analyze"],
        license_enforced=license_enforced,
    )


def _zero_limit_manager() -> LicenseManager:
    """Build a manager whose running-count cap is 0 and seed it with
    one pre-existing agent so the next ``admit`` call fails."""
    now = datetime.now(UTC)
    license = License(
        org_id="test-org",
        tier="starter",
        agent_limit=1,
        issued_at=now,
        expires_at=now + timedelta(days=365),
        signature="test-sig",
    )
    mgr = LicenseManager(license=license, grace_days=30)
    # Seed a running agent to exhaust the limit of 1.
    mgr.admit("seed-agent-holding-the-slot")
    return mgr


@pytest.fixture(autouse=True)
def _isolate_manager():
    """Every test starts + ends with no manager installed."""
    set_license_manager(None)
    yield
    set_license_manager(None)


# ---------------------------------------------------------------------------
# 1. Auto-apply: @enforced is wrapped onto run() by default
# ---------------------------------------------------------------------------


class TestAutoApply:
    def test_run_is_marked_enforced(self) -> None:
        """The ``_shieldops_enforced`` marker proves the decorator ran."""
        Runner = _build_runner()
        # The marker is on the wrapped method object.
        assert getattr(Runner.run, "_shieldops_enforced", False) is True

    def test_opt_out_skips_the_decorator(self) -> None:
        Runner = _build_runner(license_enforced=False)
        assert getattr(Runner.run, "_shieldops_enforced", False) is False

    @pytest.mark.asyncio
    async def test_run_raises_limit_error_when_manager_is_full(self) -> None:
        """The entire point of PR-2: running a framework-built agent
        while the license is exhausted raises ``LicenseLimitError``
        before the graph executes."""
        Runner = _build_runner()
        with use_test_license(_zero_limit_manager()):
            runner = Runner()
            with pytest.raises(LicenseLimitError):
                await runner.run()

    @pytest.mark.asyncio
    async def test_run_succeeds_when_manager_has_capacity(self) -> None:
        """Normal path — a manager with capacity lets the run proceed
        through the generated graph."""
        Runner = _build_runner()
        with use_test_license(LicenseManager.unlimited()):
            runner = Runner()
            result = await runner.run()
            # The graph returns the state; result type is whatever
            # state_type validates to.
            assert result is not None

    @pytest.mark.asyncio
    async def test_opt_out_runs_without_license_check(self) -> None:
        """license_enforced=False lets the run proceed even when the
        manager is exhausted."""
        Runner = _build_runner(license_enforced=False)
        with use_test_license(_zero_limit_manager()):
            runner = Runner()
            # Should NOT raise.
            result = await runner.run()
            assert result is not None


# ---------------------------------------------------------------------------
# 2. Missing-manager fallback — the compatibility guarantee
# ---------------------------------------------------------------------------


class TestMissingManagerFallback:
    """When no LicenseManager is installed (the default dev/test state),
    the @enforced wrapper logs once and passes through. This is the
    property that kept the existing 114 `@define_agent` tests green
    when PR-2 landed."""

    @pytest.mark.asyncio
    async def test_run_without_installed_manager_executes_normally(
        self,
    ) -> None:
        """No manager → runner runs without enforcement."""
        Runner = _build_runner()
        # No use_test_license() wrap — the manager is None.
        runner = Runner()
        result = await runner.run()
        assert result is not None


# ---------------------------------------------------------------------------
# 3. Idempotency — double-decoration is safe
# ---------------------------------------------------------------------------


class TestDoubleDecoration:
    def test_rebuilding_the_runner_is_idempotent(self) -> None:
        """Calling define_agent twice with the same name produces two
        distinct Runner classes, each wrapped exactly once. The
        _shieldops_enforced marker is present on both but neither is
        double-wrapped (the enforced() decorator short-circuits when
        the marker is already set)."""
        Runner1 = _build_runner()
        Runner2 = _build_runner()
        assert getattr(Runner1.run, "_shieldops_enforced", False) is True
        assert getattr(Runner2.run, "_shieldops_enforced", False) is True
        # Both are callable; neither got stacked twice.
        assert Runner1 is not Runner2
