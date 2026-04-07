"""Composition root for licensing enforcement.

The setter + getter pattern mirrors RFC #244's design section:
"`set_license_manager()` is global state behind a setter". Fine for
single-process deployments today. Multi-tenant per-request isolation
(Phase 2) comes from a subclass of :class:`LicenseManager` that resolves
per-org, swapped in via the same setter.

Tests use :class:`use_test_license` — a context manager that swaps in
an :class:`LicenseManager.unlimited` (or caller-supplied) instance and
restores the previous one on exit, **even on exception**.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

from shieldops.licensing.manager import LicenseManager

__all__ = [
    "get_license_manager",
    "set_license_manager",
    "use_test_license",
]


_manager: LicenseManager | None = None


def set_license_manager(manager: LicenseManager | None) -> None:
    """Install (or clear) the process-wide license manager."""
    global _manager
    _manager = manager


def get_license_manager() -> LicenseManager:
    """Return the currently-installed manager.

    Raises :class:`RuntimeError` if no manager is installed. Callers
    that want a no-op default in dev should install an ``unlimited``
    manager at startup, not rely on ``None``.
    """
    if _manager is None:
        raise RuntimeError(
            "No LicenseManager installed. Call set_license_manager(mgr) "
            "during app startup, or use `use_test_license()` in tests."
        )
    return _manager


@contextlib.contextmanager
def use_test_license(
    manager: LicenseManager | None = None,
) -> Iterator[LicenseManager]:
    """Test helper — swap in a manager for the duration of a block.

    Usage::

        with use_test_license() as mgr:
            # default: unlimited manager, safe for most tests
            ...

        with use_test_license(LicenseManager(license=..., grace_days=0)) as mgr:
            # pass a pre-built manager for tests that care about limits
            ...

    Restores the previous manager on exit, **including exception paths**.
    """
    previous = _manager
    mgr = manager or LicenseManager.unlimited()
    try:
        set_license_manager(mgr)
        yield mgr
    finally:
        set_license_manager(previous)
