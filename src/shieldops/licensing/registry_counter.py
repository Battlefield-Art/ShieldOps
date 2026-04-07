"""Wire LicenseGuard's agent counter to a real agent registry.

Provides:
- :class:`AgentRegistryCounter` — callable that returns the count of
  agents currently in ``"started"`` state in the registry.
- :class:`InMemoryAgentRegistry` — minimal registry useful for tests and
  embedded deployments. Production wires to the real ShieldOps agent
  registry under ``shieldops.agents.registry``.
- :func:`install_registry_counter` — convenience helper that binds a
  counter to a :class:`LicenseGuard`.
"""

from __future__ import annotations

import threading
from collections.abc import Callable

import structlog

from shieldops.licensing.guard import LicenseGuard

logger = structlog.get_logger(__name__)


class _RegistryProtocol:
    def get_status(self, agent_name: str) -> str:  # pragma: no cover - protocol stub
        ...

    def all_agents(self) -> dict[str, str]:  # pragma: no cover - protocol stub
        ...


class InMemoryAgentRegistry:
    """Minimal thread-safe agent registry for tests and embedded deployments."""

    def __init__(self) -> None:
        self._statuses: dict[str, str] = {}
        self._lock = threading.Lock()

    def set_status(self, agent_name: str, status: str) -> None:
        with self._lock:
            self._statuses[agent_name] = status

    def get_status(self, agent_name: str) -> str:
        with self._lock:
            return self._statuses.get(agent_name, "unknown")

    def all_agents(self) -> dict[str, str]:
        with self._lock:
            return dict(self._statuses)


class AgentRegistryCounter:
    """Callable adapter exposing ``int`` for ``LicenseGuard.current_agent_count``."""

    STARTED_STATES: frozenset[str] = frozenset({"started", "running"})

    def __init__(self, *, registry: _RegistryProtocol) -> None:
        self._registry = registry

    def __call__(self) -> int:
        agents = self._registry.all_agents()
        return sum(1 for status in agents.values() if status in self.STARTED_STATES)


def install_registry_counter(
    *,
    guard: LicenseGuard,
    registry: _RegistryProtocol,
) -> Callable[[], int]:
    """Bind a registry-backed counter to ``guard.current_agent_count``."""
    counter = AgentRegistryCounter(registry=registry)
    guard.current_agent_count = counter
    logger.info("license.registry_counter.installed")
    return counter
