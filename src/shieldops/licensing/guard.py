"""License enforcement guard — called at agent startup to enforce agent_limit.

Public interface::

    guard = LicenseGuard(license=current_license)
    guard.current_agent_count = lambda: len(running_agents)
    guard.check_can_start("investigation")  # raises LicenseExceededError if over limit

The guard is stateless beyond the license + counter callback; production wires
the counter to the real agent registry.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

import structlog

from shieldops.licensing.models import License

logger = structlog.get_logger(__name__)


class LicenseExceededError(Exception):
    """Raised when starting another agent would exceed the license agent limit."""

    def __init__(self, *, agent_name: str, current: int, limit: int) -> None:
        self.agent_name = agent_name
        self.current = current
        self.limit = limit
        super().__init__(
            f"License agent limit reached: cannot start '{agent_name}' "
            f"(current={current}, limit={limit})"
        )


class LicenseExpiredError(Exception):
    """Raised when the license is expired beyond grace."""


class LicenseGuard:
    """Enforces license agent_limit and expiry at agent startup."""

    def __init__(
        self,
        *,
        license: License,
        grace_days: int = 30,
        current_agent_count: Callable[[], int] | None = None,
    ) -> None:
        self._license = license
        self._grace_days = grace_days
        self.current_agent_count: Callable[[], int] = current_agent_count or (lambda: 0)

    def check_can_start(self, agent_name: str, *, now: datetime | None = None) -> None:
        """Raise LicenseExceededError if starting ``agent_name`` would exceed the limit.

        Also raises LicenseExpiredError if the license is past its grace period.
        """
        now = now or datetime.now(UTC)

        # Expiry check with grace period
        if self._license.expires_at is not None:
            grace_cutoff_days = self._days_past_expiry(now)
            if grace_cutoff_days > self._grace_days:
                raise LicenseExpiredError(
                    f"License expired {grace_cutoff_days} days ago "
                    f"(grace period: {self._grace_days} days)"
                )

        # Unlimited tier always allows
        if self._license.agent_limit < 0:
            logger.debug("license.unlimited_allow", agent=agent_name)
            return

        current = self.current_agent_count()
        if current >= self._license.agent_limit:
            logger.warning(
                "license.limit_reached",
                agent=agent_name,
                current=current,
                limit=self._license.agent_limit,
            )
            raise LicenseExceededError(
                agent_name=agent_name,
                current=current,
                limit=self._license.agent_limit,
            )
        logger.debug(
            "license.startup_allowed",
            agent=agent_name,
            current=current,
            limit=self._license.agent_limit,
        )

    def _days_past_expiry(self, now: datetime) -> int:
        if self._license.expires_at is None:
            return 0
        delta = now - self._license.expires_at
        return max(0, delta.days)
