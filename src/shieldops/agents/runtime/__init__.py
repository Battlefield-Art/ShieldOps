"""AgentRuntime — the keystone ports & adapters framework (RFC #247 PR-1).

See ghantakiran/ShieldOps#247. This package is the deep module that
makes the per-RFC ``@define_agent`` adoption stories (RFCs #244, #246)
reach all 499 agents instead of just 114.

PR-1 scope:
- ``Agent`` base class with class-attribute declarative spec
- ``AgentRuntime`` that mounts agents + drives the 7-step lifecycle
- 9 port Protocols (Transport → Hub, Policy, LicenseManager,
  Persistence, Audit, EvolutionStore, Connectors, Clock, Logger)
- In-memory adapters for all 9 ports
- The full-lifecycle contract test: one mounted agent running a node
  through license → policy → run → persist → audit → publish →
  evolution in <10 ms with zero mocks

PR-2+ wires production adapters that bridge to the real RFCs'
abstractions and ships the codemod for the 389 hand-rolled runners.
"""

from __future__ import annotations

from shieldops.agents.runtime.agent import Agent, Edge, NodeFn, node
from shieldops.agents.runtime.composition import (
    build_in_memory_runtime,
    get_agent_runtime,
    set_agent_runtime,
    use_test_agent_runtime,
)
from shieldops.agents.runtime.events import END, MountedAgent, RunRecord
from shieldops.agents.runtime.ports import (
    AuditPort,
    Clock,
    ConnectorRouterPort,
    EvolutionStorePort,
    LicenseManagerPort,
    Logger,
    PersistencePort,
    PolicyPort,
    WSHubPort,
)
from shieldops.agents.runtime.runtime import AgentRuntime

__all__ = [
    "END",
    "Agent",
    "AgentRuntime",
    "AuditPort",
    "Clock",
    "ConnectorRouterPort",
    "Edge",
    "EvolutionStorePort",
    "LicenseManagerPort",
    "Logger",
    "MountedAgent",
    "NodeFn",
    "PersistencePort",
    "PolicyPort",
    "RunRecord",
    "WSHubPort",
    "build_in_memory_runtime",
    "get_agent_runtime",
    "node",
    "set_agent_runtime",
    "use_test_agent_runtime",
]
