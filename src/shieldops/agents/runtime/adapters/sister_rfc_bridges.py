"""Sister-RFC bridge adapters for the AgentRuntime — #247 PR-2.

See ghantakiran/ShieldOps#247. PR-1 landed the pure :class:`AgentRuntime`
core over 9 runtime-local ports + in-memory adapters. PR-2 wires the
three most-used ports to the actual sister-RFC abstractions:

- :class:`LicenseManagerBridge` → RFC #244's ``LicenseManager``
- :class:`EvolutionStoreBridge` → RFC #246's ``EvolutionStore``
- :class:`WSHubBridge`          → RFC #242's ``Hub``

These bridges are thin by design: each one holds zero logic of its
own. They:

1. Resolve the installed sister-RFC subsystem lazily via its
   composition root — so ``use_test_X(...)`` round-trips work without
   re-assembling the runtime.
2. Translate the runtime's port vocabulary into the sister RFC's
   vocabulary (e.g. ``EvolutionStorePort.record_run`` kwargs → a
   ``RunOutcome`` plus ``handle.record(outcome)``).
3. Swallow missing-subsystem ``RuntimeError`` s and broken-subsystem
   exceptions, logging at warning and returning a safe default. Same
   compatibility guarantee as the other RFC PR-2 landings — a bug in
   one subsystem cannot crash the agent runtime.

Composition roots remain the single source of truth for "which
adapter is installed". Tests that want to exercise the sister
subsystem directly use the existing in-memory adapters from
:mod:`shieldops.agents.runtime.adapters.in_memory_ports`.
"""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.composition import get_license_manager
from shieldops.licensing.manager import LicenseError
from shieldops.utils.evolution.composition import get_evolution_store
from shieldops.utils.evolution.store import RunOutcome

logger = structlog.get_logger(__name__)


__all__ = [
    "EvolutionStoreBridge",
    "LicenseManagerBridge",
    "WSHubBridge",
]


# ---------------------------------------------------------------------------
# #244: LicenseManagerBridge
# ---------------------------------------------------------------------------


class LicenseManagerBridge:
    """Implements :class:`LicenseManagerPort` by calling #244's manager.

    The port's ``check(agent_name, tenant_id) -> bool`` is a pure
    admissibility query that must NOT reserve a slot — the runtime
    calls ``check`` before the license-enforced ``@enforced`` wrapper
    in the per-agent runner (which in turn calls ``admit`` and holds
    the lease through the run). This lets the runtime short-circuit
    early with a clear "license full" response before any graph is
    built.

    Missing-manager semantics match the rest of the RFC family: when
    no manager is installed, ``check`` returns ``True`` (admit). This
    keeps dev/test environments green — production opts in by calling
    ``set_license_manager(...)`` during ``app.py`` lifespan.
    """

    def check(self, agent_name: str, tenant_id: str) -> bool:
        """Return ``True`` if ``agent_name`` may start.

        A real attempt to ``admit`` would have side effects (it
        reserves a slot); instead we consult the manager's running
        count against the license limit. Expired / invalid licenses
        also return ``False``.
        """
        try:
            manager = get_license_manager()
        except RuntimeError:
            # Default-admit when no manager is installed.
            logger.debug(
                "runtime.license_bridge.manager_not_installed",
                agent=agent_name,
                tenant=tenant_id,
            )
            return True

        try:
            # LicenseManager exposes `admit(...)` as the only write path.
            # We use its public read-only query (`can_admit`) when it
            # exists; fall back to a dry-run admit/release otherwise.
            can_admit = getattr(manager, "can_admit", None)
            if callable(can_admit):
                return bool(can_admit(agent_name))
            lease = manager.admit(agent_name)
            lease.release()
            return True
        except LicenseError as exc:
            logger.info(
                "runtime.license_bridge.denied",
                agent=agent_name,
                tenant=tenant_id,
                reason=type(exc).__name__,
            )
            return False
        except Exception as exc:  # noqa: BLE001
            # Broken manager — fail open so the runtime stays up.
            logger.warning(
                "runtime.license_bridge.check_failed",
                agent=agent_name,
                tenant=tenant_id,
                error=str(exc),
            )
            return True


# ---------------------------------------------------------------------------
# #246: EvolutionStoreBridge
# ---------------------------------------------------------------------------


class EvolutionStoreBridge:
    """Implements :class:`EvolutionStorePort` by calling #246's store.

    Translates the runtime's ``record_run`` kwargs into a
    :class:`RunOutcome` and hands it to the per-agent handle. Missing
    / broken store is a warning, never a crash — matches the
    layered exception safety in #246 PR-2 ``tracked_run``.
    """

    async def record_run(
        self,
        *,
        agent_name: str,
        tenant_id: str,
        success: bool,
        latency_ms: float,
        node_count: int,
    ) -> None:
        outcome = RunOutcome(
            success=success,
            latency_ms=latency_ms,
            metadata={
                "source": "agent_runtime",
                "node_count": node_count,
            },
        )

        try:
            store = get_evolution_store()
        except RuntimeError:
            logger.debug(
                "runtime.evolution_bridge.store_not_installed",
                agent=agent_name,
                tenant=tenant_id,
            )
            return

        try:
            handle = store.for_agent(agent_name, tenant_id=tenant_id or "default")
            handle.record(outcome)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "runtime.evolution_bridge.record_failed",
                agent=agent_name,
                tenant=tenant_id,
                error=str(exc),
            )


# ---------------------------------------------------------------------------
# #242: WSHubBridge
# ---------------------------------------------------------------------------


class WSHubBridge:
    """Implements :class:`WSHubPort` by calling #242's Hub.

    The runtime emits lifecycle events (``agent.started``,
    ``agent.finished``, ``agent.failed``) via ``publish(channel,
    event)``. The bridge translates the plain dict event into the
    Hub's :class:`Event` value object so the core stays pure.
    """

    async def publish(self, channel: str, event: dict[str, Any]) -> None:
        # Local import keeps the import graph tidy — runtime code does
        # not load the WS Hub unless this bridge is actually used.
        from shieldops.api.ws.composition import get_ws_hub
        from shieldops.api.ws.core import Event

        try:
            hub = get_ws_hub()
        except RuntimeError:
            logger.debug("runtime.ws_bridge.hub_not_installed", channel=channel)
            return

        kind = str(event.get("kind") or event.get("type") or "agent.event")
        data = {k: v for k, v in event.items() if k not in ("kind", "type")}
        try:
            await hub.publish(channel, Event(kind=kind, data=data))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "runtime.ws_bridge.publish_failed",
                channel=channel,
                kind=kind,
                error=str(exc),
            )
