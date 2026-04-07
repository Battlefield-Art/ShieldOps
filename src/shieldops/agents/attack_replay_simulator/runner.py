"""Attack Replay Simulator Agent runner -- entry point.

Takes runtime configuration, constructs the LangGraph,
runs end-to-end, and returns completed ARS state.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.attack_replay_simulator.graph import (
    create_attack_replay_simulator_graph,
)
from shieldops.agents.attack_replay_simulator.models import (
    AttackReplaySimulatorState,
)
from shieldops.agents.attack_replay_simulator.nodes import (
    set_toolkit,
)
from shieldops.agents.attack_replay_simulator.tools import (
    AttackReplaySimulatorToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class AttackReplaySimulatorRunner:
    """Runs attack replay simulator workflows.

    Usage:
        runner = AttackReplaySimulatorRunner(
            technique_library=library,
            sandbox_manager=manager,
        )
        result = await runner.run(tenant_id="t-123")
    """

    def __init__(
        self,
        technique_library: Any | None = None,
        sandbox_manager: Any | None = None,
        replay_engine: Any | None = None,
        telemetry_collector: Any | None = None,
        detection_evaluator: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AttackReplaySimulatorToolkit(
            technique_library=technique_library,
            sandbox_manager=sandbox_manager,
            replay_engine=replay_engine,
            telemetry_collector=telemetry_collector,
            detection_evaluator=detection_evaluator,
            repository=repository,
        )
        # Configure module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build compiled graph
        graph = create_attack_replay_simulator_graph()
        self._app = graph.compile()

        # In-memory store of completed runs
        self._results: dict[str, AttackReplaySimulatorState] = {}

    @enforced("attack_replay_simulator")
    async def run(
        self,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> AttackReplaySimulatorState:
        """Run a full attack replay simulation cycle.

        Args:
            tenant_id: Tenant ID for scoped queries.
            config: Optional configuration overrides.

        Returns:
            Completed AttackReplaySimulatorState.
        """
        request_id = f"ars-{uuid4().hex[:12]}"

        logger.info(
            "ars_started",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        initial_state = AttackReplaySimulatorState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "tenant_id": tenant_id,
                    },
                },
            )

            final_state = AttackReplaySimulatorState.model_validate(final_dict)

            # Calculate total duration
            if final_state.session_start:
                elapsed = datetime.now(UTC) - final_state.session_start
                final_state.session_duration_ms = int(elapsed.total_seconds() * 1000)

            logger.info(
                "ars_completed",
                request_id=request_id,
                techniques=final_state.technique_count,
                executions=len(final_state.executions),
                detected=final_state.detected_count,
                missed=final_state.missed_count,
                duration_ms=final_state.session_duration_ms,
            )

            self._results[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "ars_failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = AttackReplaySimulatorState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> AttackReplaySimulatorState | None:
        """Retrieve a completed run by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all runs with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": st.tenant_id,
                "stage": st.stage,
                "status": st.current_step,
                "techniques": st.technique_count,
                "executions": len(st.executions),
                "detected": st.detected_count,
                "missed": st.missed_count,
                "duration_ms": st.session_duration_ms,
                "error": st.error,
            }
            for rid, st in self._results.items()
        ]
