"""Public types for the AgentRuntime.

Pure data — no behavior. The runtime reads and writes these; adapters
translate at the boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# Sentinel for end-of-graph edges.
END = "__END__"


@dataclass(frozen=True)
class RunRecord:
    """What the runtime persists after a run.

    The caller of ``MountedAgent.run(input)`` gets this back as the
    result. Services that want the agent's final state access
    ``final_state``; audit and evolution tracking already happened
    inside the lifecycle.
    """

    run_id: str
    agent_name: str
    tenant_id: str
    final_state: Any
    success: bool
    latency_ms: float
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    error: str | None = None
    node_count: int = 0


@dataclass
class MountedAgent:
    """A bound agent class + the runtime that will execute it.

    Returned by :meth:`AgentRuntime.mount`. Tests and routes call
    ``mounted.run(input, tenant_id="...")`` to drive the agent
    through its 7-step lifecycle.
    """

    agent_cls: type
    runtime: Any  # AgentRuntime — late-resolved to avoid circular import
    last_run_id: str | None = None

    async def run(self, input_state: Any, *, tenant_id: str = "default") -> RunRecord:
        return await self.runtime._execute(self, input_state, tenant_id=tenant_id)
