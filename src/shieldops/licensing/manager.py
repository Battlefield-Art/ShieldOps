"""LicenseManager + AgentLease — single owner of 'can this agent start?'.

See RFC #244 (ghantakiran/ShieldOps#244) for the full design. This
module replaces the 4-layer ``startup_hook → guard → counter → registry``
indirection with **one class per scope** (per-process in single-tenant,
per-org in multi-tenant) that owns the running set authoritatively.

The subtlest invariant is that :meth:`LicenseManager.admit` returns a
context manager — :class:`AgentLease` — whose ``__exit__`` always
decrements the running count, even on exception. This makes the "notify
started / notify stopped" pairing leak-free by construction: there is
no separate ``notify_stopped`` to forget.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.licensing.models import License

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Errors — collapse the guard.LicenseExpiredError / validator.LicenseExpiredError
# duplication into one class. RFC #244 PR-4 deletes guard.LicenseExpiredError.
# ---------------------------------------------------------------------------


class LicenseError(Exception):
    """Base class for license enforcement failures."""


class LicenseLimitError(LicenseError):
    """Starting another agent would exceed the license agent limit.

    Renamed from ``LicenseExceededError`` in the old guard.py to match
    the Pythonic convention of ``*Error`` for exceptions and to make it
    clear this is about a numeric limit, not expiry.
    """

    def __init__(self, *, agent_name: str, current: int, limit: int) -> None:
        self.agent_name = agent_name
        self.current = current
        self.limit = limit
        super().__init__(
            f"License agent limit reached: cannot start {agent_name!r} "
            f"(current={current}, limit={limit})"
        )


class LicenseExpiredError(LicenseError):
    """The license is expired beyond its grace period."""

    def __init__(self, *, days_past_grace: int, grace_days: int) -> None:
        self.days_past_grace = days_past_grace
        self.grace_days = grace_days
        super().__init__(
            f"License expired {days_past_grace} days past grace period ({grace_days} days)"
        )


# ---------------------------------------------------------------------------
# AgentLease — context manager that owns the decrement on exit
# ---------------------------------------------------------------------------


class AgentLease:
    """A check-in/check-out for one agent's running state.

    Created only by :meth:`LicenseManager.admit`. The manager holds a
    reference to the lease's source manager so the lease can release
    itself without the caller needing to know how to decrement.

    Supports both sync and async context-manager protocols so runners
    that use ``with`` and runners that use ``async with`` both work
    without an extra wrapper.
    """

    __slots__ = ("_manager", "_agent_name", "_released")

    def __init__(self, manager: LicenseManager, agent_name: str) -> None:
        self._manager = manager
        self._agent_name = agent_name
        self._released = False

    @property
    def agent_name(self) -> str:
        return self._agent_name

    def release(self) -> None:
        """Idempotent release. Safe to call multiple times."""
        if self._released:
            return
        self._released = True
        self._manager._release(self._agent_name)

    # -- sync context manager --------------------------------------------

    def __enter__(self) -> AgentLease:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.release()

    # -- async context manager -------------------------------------------

    async def __aenter__(self) -> AgentLease:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        self.release()


# ---------------------------------------------------------------------------
# LicenseManager — single owner
# ---------------------------------------------------------------------------


# Clock type: a zero-arg callable returning a UTC datetime. Defaults to
# ``datetime.now(UTC)`` but tests inject a frozen clock.
Clock = Callable[[], datetime]


def _default_clock() -> datetime:
    return datetime.now(UTC)


class LicenseManager:
    """One instance per license scope.

    Single-tenant deployments construct one per process and store it on
    ``app.state.license_manager``. Multi-tenant deployments keep a
    ``dict[str, LicenseManager]`` keyed by ``org_id`` and look one up
    per request.

    The manager owns its running set — there is no callback attribute,
    no module-level global, no counter-adapter protocol. Constructor
    injection only.
    """

    def __init__(
        self,
        *,
        license: License,
        grace_days: int = 30,
        clock: Clock = _default_clock,
    ) -> None:
        self._license = license
        self._grace_days = grace_days
        self._clock = clock

        # Authoritative running set. Lives here, not in a separate counter.
        self._running: set[str] = set()
        self._lock = threading.Lock()

    # -- read-only properties --------------------------------------------

    @property
    def license(self) -> License:
        return self._license

    @property
    def running_count(self) -> int:
        with self._lock:
            return len(self._running)

    @property
    def running_agents(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._running)

    # -- factory for tests -----------------------------------------------

    @classmethod
    def unlimited(cls, *, org_id: str = "test", grace_days: int = 30) -> LicenseManager:
        """Test factory — builds an ``UNLIMITED`` license (agent_limit=-1).

        Used by :class:`use_test_license` and by tests that want to
        exercise a runner without caring about license semantics.
        """
        now = datetime.now(UTC)
        license = License(
            org_id=org_id,
            tier="unlimited",
            agent_limit=-1,
            issued_at=now,
            expires_at=now.replace(year=now.year + 100),
            signature="test",
        )
        return cls(license=license, grace_days=grace_days)

    # -- the ONLY production entry point ---------------------------------

    def admit(self, agent_name: str) -> AgentLease:
        """Check whether ``agent_name`` may start; if so, reserve a slot.

        Returns an :class:`AgentLease` context manager. The caller MUST
        use it as a context manager (``with manager.admit(...):``) so
        the slot is released on exit — including exception paths.

        Raises:
            LicenseExpiredError: if the license is past its grace period.
            LicenseLimitError: if starting another agent would exceed
                the license's ``agent_limit``.
        """
        now = self._clock()

        # Expiry check with grace period.
        if self._license.expires_at is not None:
            days_past = (now - self._license.expires_at).days
            if days_past > self._grace_days:
                raise LicenseExpiredError(
                    days_past_grace=days_past,
                    grace_days=self._grace_days,
                )

        # Unlimited tier always allows.
        if self._license.agent_limit < 0:
            with self._lock:
                self._running.add(agent_name)
            logger.debug(
                "license.admit.unlimited",
                agent=agent_name,
                org_id=self._license.org_id,
            )
            return AgentLease(self, agent_name)

        with self._lock:
            current = len(self._running)
            if current >= self._license.agent_limit and agent_name not in self._running:
                logger.warning(
                    "license.limit_reached",
                    agent=agent_name,
                    current=current,
                    limit=self._license.agent_limit,
                    org_id=self._license.org_id,
                )
                raise LicenseLimitError(
                    agent_name=agent_name,
                    current=current,
                    limit=self._license.agent_limit,
                )
            self._running.add(agent_name)
            logger.debug(
                "license.admit",
                agent=agent_name,
                current=len(self._running),
                limit=self._license.agent_limit,
                org_id=self._license.org_id,
            )

        return AgentLease(self, agent_name)

    # -- called by AgentLease on exit ------------------------------------

    def _release(self, agent_name: str) -> None:
        with self._lock:
            self._running.discard(agent_name)
        logger.debug(
            "license.release",
            agent=agent_name,
            remaining=self.running_count,
            org_id=self._license.org_id,
        )

    # -- support async callers via asyncio.Lock wrapper ------------------

    async def admit_async(self, agent_name: str) -> AgentLease:
        """Async variant that yields control briefly.

        The underlying synchronisation is a :class:`threading.Lock` so
        this method does not actually block on I/O — but making it an
        ``async def`` lets callers use ``async with`` consistently.
        """
        # Yield once so we behave like a true coroutine in async tests
        # that rely on event-loop ordering.
        await asyncio.sleep(0)
        return self.admit(agent_name)
