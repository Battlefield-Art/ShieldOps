"""``@enforced`` decorator — the 99%-caller adoption mechanism.

See RFC #244 (ghantakiran/ShieldOps#244). Agent runners wrap their
``run`` method with ``@enforced("agent_id")`` and get license
enforcement for free — the decorator:

1. Acquires an :class:`AgentLease` before calling the wrapped method.
2. Calls the wrapped method inside the lease's context.
3. Releases the lease in a ``finally`` block, even on exception.

The `_shieldops_enforced` marker attribute is attached to the wrapped
function so the RFC #244 codemod (and the future RFC #247 framework
patch) can detect already-enforced functions and no-op the re-application.
Double-decoration is safe.

Also provides :func:`enforce` — the async context-manager form for
code that wants explicit control.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
from collections.abc import AsyncIterator, Callable
from typing import Any, TypeVar

from shieldops.licensing.composition import get_license_manager
from shieldops.licensing.manager import AgentLease

F = TypeVar("F", bound=Callable[..., Any])

# Marker attribute — used by:
# - RFC #244 codemod (scripts/codemods/licensing_enforce.py, landing in PR-3)
# - RFC #247 framework patch (agents/framework.py::define_agent)
# Both check this flag so re-applying @enforced is a no-op.
_ENFORCED_MARKER = "_shieldops_enforced"


def enforced(
    agent_id: str,
    *,
    tenant: str | Callable[..., str] | None = None,
) -> Callable[[F], F]:
    """Wrap an agent runner's entry point with license enforcement.

    Args:
        agent_id: The logical agent name. Used as the key in the
            manager's running set. Two runs of the same ``agent_id``
            count as two slots unless the second's ``agent_name`` is
            already present (then it's a no-op).
        tenant: Optional. Either a static string (for single-tenant
            deployments) or a callable ``(self, *args, **kwargs) -> str``
            that extracts the tenant from the call's arguments. Not
            used in PR-1 (multi-tenant is Phase 2) but accepted for
            signature stability so callers can adopt it now.

    The wrapped function may be sync or async; the decorator detects
    via :func:`inspect.iscoroutinefunction` and wraps accordingly.

    Double-decoration is safe — the marker attribute short-circuits
    the second application.

    Raises ``LicenseLimitError`` / ``LicenseExpiredError`` from the
    wrapped function if enforcement fails. Agent code cannot intercept
    these — they propagate to the caller so the request fails with
    the correct status.
    """
    # `tenant` is reserved for Phase 2 (per-request per-org managers).
    # For now we just capture it so call sites can adopt early.
    _ = tenant

    def decorator(func: F) -> F:
        # Short-circuit: if already enforced, return the original.
        if getattr(func, _ENFORCED_MARKER, False):
            return func

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                manager = get_license_manager()
                lease = manager.admit(agent_id)
                try:
                    return await func(*args, **kwargs)
                finally:
                    lease.release()

            setattr(async_wrapper, _ENFORCED_MARKER, True)
            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            manager = get_license_manager()
            lease = manager.admit(agent_id)
            try:
                return func(*args, **kwargs)
            finally:
                lease.release()

        setattr(sync_wrapper, _ENFORCED_MARKER, True)
        return sync_wrapper  # type: ignore[return-value]

    return decorator


@contextlib.asynccontextmanager
async def enforce(agent_id: str) -> AsyncIterator[AgentLease]:
    """Async-context-manager equivalent of :func:`enforced`.

    Usage::

        async def run_custom():
            async with enforce("my_agent") as lease:
                ...  # do work; lease auto-releases on exit

    Preferred in code that already uses ``async with`` idiomatically
    and doesn't want to add a decorator just for one call site.
    """
    manager = get_license_manager()
    lease = manager.admit(agent_id)
    try:
        yield lease
    finally:
        lease.release()
