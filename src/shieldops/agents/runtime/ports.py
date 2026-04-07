"""Port Protocols for the AgentRuntime core.

The 9 ports here map one-to-one to the sister RFCs' abstractions:

- ``WSHubPort``          → RFC #242 (shieldops.api.ws.core.Hub)
- ``PolicyPort``         → RFC #243 (shieldops.api.policy.RequestPolicyEngine)
- ``LicenseManagerPort`` → RFC #244 (shieldops.licensing.LicenseManager)
- ``PersistencePort``    → RFC #245 (shieldops.db.fetch + services)
- ``AuditPort``          → RFC #245 (shieldops.db.audit.log_audit)
- ``EvolutionStorePort`` → RFC #246 (shieldops.utils.evolution.EvolutionStore)
- ``ConnectorRouterPort``→ existing shieldops.connectors (bridged in PR-2)
- ``Clock``              → injectable wall clock
- ``Logger``             → structlog-compatible

PR-1 defines them as runtime-local Protocols so the runtime can land
pure-additive. PR-2 wires production adapters that bridge each port
to the real sister-RFC object.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class WSHubPort(Protocol):
    """Publishes agent lifecycle events. Maps to RFC #242's Hub."""

    async def publish(self, channel: str, event: dict[str, Any]) -> None: ...


@runtime_checkable
class PolicyPort(Protocol):
    """Evaluates OPA-style policy decisions before sensitive node execution."""

    async def evaluate(self, action: str, context: dict[str, Any]) -> bool: ...


@runtime_checkable
class LicenseManagerPort(Protocol):
    """Maps to RFC #244's LicenseManager — gates agent startup."""

    def check(self, agent_name: str, tenant_id: str) -> bool: ...


@runtime_checkable
class PersistencePort(Protocol):
    """Maps to RFC #245's fetch/services — persists run state."""

    async def save_state(self, run_id: str, state: dict[str, Any]) -> None: ...


@runtime_checkable
class AuditPort(Protocol):
    """Maps to RFC #245's audit.log_audit."""

    async def log(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        metadata: dict[str, Any],
    ) -> None: ...


@runtime_checkable
class EvolutionStorePort(Protocol):
    """Maps to RFC #246's EvolutionStore — records run outcomes."""

    async def record_run(
        self,
        *,
        agent_name: str,
        tenant_id: str,
        success: bool,
        latency_ms: float,
        node_count: int,
    ) -> None: ...


@runtime_checkable
class ConnectorRouterPort(Protocol):
    """Vendor API calls — bridged to shieldops.connectors in PR-2."""

    async def call(self, vendor: str, operation: str, **kwargs: Any) -> dict[str, Any]: ...


@runtime_checkable
class Clock(Protocol):
    def now(self) -> float: ...
    def monotonic_ms(self) -> float: ...


@runtime_checkable
class Logger(Protocol):
    def bind(self, **kw: Any) -> Logger: ...
    def info(self, msg: str, **kw: Any) -> None: ...
    def warning(self, msg: str, **kw: Any) -> None: ...
    def error(self, msg: str, **kw: Any) -> None: ...
