"""License startup hook — the single entry point agent runners call.

Agents call :func:`check_startup` before building their graph, then
:func:`notify_started` when the graph has been created, and
:func:`notify_stopped` when they shut down.

When no guard is installed (``set_guard(None)``) all startups are allowed —
this is the default in dev/test environments.
"""

from __future__ import annotations

import threading

import structlog

from shieldops.licensing.guard import LicenseGuard

logger = structlog.get_logger(__name__)

_guard: LicenseGuard | None = None
_running_count: int = 0
_running_agents: set[str] = set()
_lock = threading.Lock()


def set_guard(guard: LicenseGuard | None) -> None:
    """Install (or clear) the active license guard."""
    global _guard
    _guard = guard


def get_guard() -> LicenseGuard | None:
    return _guard


def get_running_count() -> int:
    """Return the current running-agent count (thread-safe snapshot)."""
    with _lock:
        return _running_count


def reset_running_count() -> None:
    """Test helper: zero the counter and cleared set."""
    global _running_count
    with _lock:
        _running_count = 0
        _running_agents.clear()


def check_startup(agent_name: str) -> None:
    """Raise LicenseExceededError / LicenseExpiredError if startup not allowed.

    No-op when no guard is installed.
    """
    if _guard is None:
        logger.debug("license.hook.no_guard_installed", agent=agent_name)
        return
    _guard.check_can_start(agent_name)


def notify_started(agent_name: str) -> None:
    """Record that an agent has successfully started."""
    global _running_count
    with _lock:
        if agent_name not in _running_agents:
            _running_agents.add(agent_name)
            _running_count += 1
    logger.info("license.hook.agent_started", agent=agent_name, total=_running_count)


def notify_stopped(agent_name: str) -> None:
    """Record that an agent has stopped."""
    global _running_count
    with _lock:
        if agent_name in _running_agents:
            _running_agents.discard(agent_name)
            _running_count = max(0, _running_count - 1)
    logger.info("license.hook.agent_stopped", agent=agent_name, total=_running_count)
