"""In-memory adapters for the AgentRuntime ports.

Each adapter captures every call so contract tests can assert on
ordering + content. Production adapters (PR-2) bridge to the real
sister-RFC objects (RFC #242 Hub, #243 Engine, #244 Manager, #245
fetch+audit, #246 EvolutionStore).
"""

from __future__ import annotations

from shieldops.agents.runtime.adapters.in_memory_ports import (
    AllowAllPolicy,
    CapturingAuditLog,
    CapturingHub,
    DenyPolicy,
    InMemoryConnectorRouter,
    InMemoryEvolutionRecorder,
    InMemoryLicenseManager,
    InMemoryPersistence,
    ManualClock,
    NullAgentLogger,
    ScriptedConnectorRouter,
)

__all__ = [
    "AllowAllPolicy",
    "CapturingAuditLog",
    "CapturingHub",
    "DenyPolicy",
    "InMemoryConnectorRouter",
    "InMemoryEvolutionRecorder",
    "InMemoryLicenseManager",
    "InMemoryPersistence",
    "ManualClock",
    "NullAgentLogger",
    "ScriptedConnectorRouter",
]
