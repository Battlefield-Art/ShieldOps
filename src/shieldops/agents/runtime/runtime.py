"""AgentRuntime — the 7-step lifecycle orchestrator.

Per-run lifecycle (each step is observable + testable):

    1. License check (LicenseManagerPort.check)
    2. Resolve + mount toolkit (Agent.toolkit_factory())
    3. Walk nodes via edges, per-node:
         3a. Policy gate (PolicyPort.evaluate) if node ∈ policy_actions
         3b. Execute node_fn(state, toolkit)
         3c. Persist state (PersistencePort.save_state)
         3d. Audit log (AuditPort.log)
         3e. Publish lifecycle event (WSHubPort.publish)
    4. On terminal: EvolutionStorePort.record_run

Every step is wrapped by the runtime, not the agent author. An agent
author writes a ~30-line class declaration and gets all 7 steps for free.

The runtime has zero imports from ``fastapi``, ``starlette``, ``redis``,
``httpx``, ``langchain_*``, ``opa``, ``structlog``. Only from
``ports`` and ``events``. Lint rule ``SHOP-003`` will enforce this.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from shieldops.agents.runtime.agent import Agent, ConditionalEdge, Edge
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


@dataclass(frozen=True)
class AgentRuntime:
    """Pure orchestration layer. Depends only on injected ports."""

    connectors: ConnectorRouterPort
    policy: PolicyPort
    hub: WSHubPort
    evolution: EvolutionStorePort
    license: LicenseManagerPort
    persist: PersistencePort
    audit: AuditPort
    clock: Clock
    log: Logger

    def mount(self, agent_cls: type[Agent]) -> MountedAgent:
        """Bind an agent class to this runtime. Returns a handle that
        routes / tests call ``.run(input, tenant_id=...)`` on."""
        return MountedAgent(agent_cls=agent_cls, runtime=self)

    async def _execute(
        self,
        mounted: MountedAgent,
        input_state: Any,
        *,
        tenant_id: str,
    ) -> RunRecord:
        """Drive one run through the 7-step lifecycle."""
        cls = mounted.agent_cls
        run_id = uuid4().hex[:16]
        mounted.last_run_id = run_id
        log = self.log.bind(agent=cls.name, tenant_id=tenant_id, run_id=run_id)
        start_ms = self.clock.monotonic_ms()

        # ---- STEP 1: license check -----------------------------------
        if cls.license_feature is not None and not self.license.check(
            cls.license_feature, tenant_id
        ):
            log.warning("agent.license_denied", feature=cls.license_feature)
            await self.audit.log(
                actor=f"agent:{cls.name}",
                action="agent.license_denied",
                target=cls.name,
                metadata={"feature": cls.license_feature, "tenant_id": tenant_id},
            )
            record = RunRecord(
                run_id=run_id,
                agent_name=cls.name,
                tenant_id=tenant_id,
                final_state=input_state,
                success=False,
                latency_ms=self.clock.monotonic_ms() - start_ms,
                error="license_denied",
            )
            await self._record_terminal(record)
            return record

        # ---- STEP 2: mount toolkit -----------------------------------
        toolkit = cls.toolkit_factory()
        log.info("agent.mount", toolkit=type(toolkit).__name__)

        # ---- STEP 3: walk nodes --------------------------------------
        state = input_state
        node_count = 0
        current: str = cls.entry
        error: str | None = None
        success = True

        try:
            while current != END:
                node_fn = cls.nodes.get(current)
                if node_fn is None:
                    raise KeyError(f"unknown node: {current}")

                # 3a: policy gate if declared
                action = cls.policy_actions.get(current)
                if action is not None:
                    allowed = await self.policy.evaluate(
                        action, {"tenant_id": tenant_id, "agent": cls.name}
                    )
                    if not allowed:
                        raise PermissionError(f"policy denied {action} on {cls.name}")

                # 3b: execute the node
                state = await node_fn(state, toolkit)
                node_count += 1

                # 3c: persist state (best-effort; wrapped)
                with contextlib.suppress(Exception):
                    await self.persist.save_state(run_id, _to_dict(state))

                # 3d: audit log
                with contextlib.suppress(Exception):
                    await self.audit.log(
                        actor=f"agent:{cls.name}",
                        action="agent.node",
                        target=f"{cls.name}/{current}",
                        metadata={"run_id": run_id, "tenant_id": tenant_id},
                    )

                # 3e: publish lifecycle event
                with contextlib.suppress(Exception):
                    await self.hub.publish(
                        f"agent.{cls.name}.{run_id}",
                        {
                            "node": current,
                            "state": _to_dict(state),
                        },
                    )

                # Walk to next node via edges
                current = _next_node(cls.edges, current, state)

        except Exception as exc:  # noqa: BLE001
            success = False
            error = str(exc)
            log.error("agent.node_failed", current_node=current, error=error)

        # ---- STEP 4: terminal — record the run ------------------------
        elapsed = self.clock.monotonic_ms() - start_ms
        record = RunRecord(
            run_id=run_id,
            agent_name=cls.name,
            tenant_id=tenant_id,
            final_state=state,
            success=success,
            latency_ms=elapsed,
            error=error,
            node_count=node_count,
        )
        await self._record_terminal(record)
        return record

    async def _record_terminal(self, record: RunRecord) -> None:
        """Record the run outcome to the evolution store + hub.
        Wrapped defensively so a bug in a sister RFC cannot crash agent code."""
        with contextlib.suppress(Exception):
            await self.evolution.record_run(
                agent_name=record.agent_name,
                tenant_id=record.tenant_id,
                success=record.success,
                latency_ms=record.latency_ms,
                node_count=record.node_count,
            )
        with contextlib.suppress(Exception):
            await self.hub.publish(
                f"agent.{record.agent_name}.{record.run_id}.terminal",
                {"success": record.success, "latency_ms": record.latency_ms},
            )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _next_node(edges: list[Edge | ConditionalEdge], current: str, state: Any) -> str:
    """Walk the edges list to find the next node from ``current``."""
    for e in edges:
        if e.source != current:
            continue
        if isinstance(e, Edge):
            return e.target
        if isinstance(e, ConditionalEdge):
            key = e.predicate(state)
            next_node = e.routes.get(key)
            if next_node is None:
                raise KeyError(
                    f"conditional edge {current!r} returned {key!r} but no route matches"
                )
            return next_node
    # No edge found — treat as end of graph.
    return END


def _to_dict(state: Any) -> dict[str, Any]:
    """Best-effort state → dict for persistence + event payload."""
    if hasattr(state, "model_dump"):
        return state.model_dump()  # type: ignore[no-any-return]
    if hasattr(state, "__dict__"):
        return {k: v for k, v in state.__dict__.items() if not k.startswith("_")}
    if isinstance(state, dict):
        return state
    return {"value": state}
