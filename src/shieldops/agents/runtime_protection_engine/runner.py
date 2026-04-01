"""Runtime Protection Engine Agent runner -- entry point for protection cycles.

Takes runtime configuration, constructs the LangGraph,
runs end-to-end, and returns completed RPE state.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.runtime_protection_engine.graph import (
    create_runtime_protection_engine_graph,
)
from shieldops.agents.runtime_protection_engine.models import (
    RuntimeProtectionEngineState,
)
from shieldops.agents.runtime_protection_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.runtime_protection_engine.tools import (
    RuntimeProtectionEngineToolkit,
)

logger = structlog.get_logger()


class RuntimeProtectionEngineRunner:
    """Runs runtime protection engine workflows.

    Usage:
        runner = RuntimeProtectionEngineRunner(
            telemetry_collector=collector,
            policy_engine=opa,
        )
        result = await runner.run(tenant_id="t-123")
    """

    def __init__(
        self,
        telemetry_collector: Any | None = None,
        behavior_analyzer: Any | None = None,
        anomaly_detector: Any | None = None,
        policy_engine: Any | None = None,
        alert_manager: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = RuntimeProtectionEngineToolkit(
            telemetry_collector=telemetry_collector,
            behavior_analyzer=behavior_analyzer,
            anomaly_detector=anomaly_detector,
            policy_engine=policy_engine,
            alert_manager=alert_manager,
            repository=repository,
        )
        # Configure module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build compiled graph
        graph = create_runtime_protection_engine_graph()
        self._app = graph.compile()

        # In-memory store of completed runs
        self._results: dict[str, RuntimeProtectionEngineState] = {}

    async def run(
        self,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> RuntimeProtectionEngineState:
        """Run a full runtime protection cycle.

        Args:
            tenant_id: Tenant ID for scoped queries.
            config: Optional configuration overrides.

        Returns:
            Completed RuntimeProtectionEngineState.
        """
        request_id = f"rpe-{uuid4().hex[:12]}"

        logger.info(
            "rpe_started",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        initial_state = RuntimeProtectionEngineState(
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

            final_state = RuntimeProtectionEngineState.model_validate(final_dict)

            # Calculate total duration
            if final_state.session_start:
                elapsed = datetime.now(UTC) - final_state.session_start
                final_state.session_duration_ms = int(elapsed.total_seconds() * 1000)

            logger.info(
                "rpe_completed",
                request_id=request_id,
                telemetry=len(final_state.telemetry),
                behaviors=len(final_state.behaviors),
                anomalies=final_state.anomaly_count,
                blocked=final_state.blocked_count,
                alerts=final_state.alert_count,
                duration_ms=final_state.session_duration_ms,
            )

            self._results[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "rpe_failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = RuntimeProtectionEngineState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> RuntimeProtectionEngineState | None:
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
                "telemetry": len(st.telemetry),
                "behaviors": len(st.behaviors),
                "anomalies": st.anomaly_count,
                "blocked": st.blocked_count,
                "alerts": st.alert_count,
                "duration_ms": st.session_duration_ms,
                "error": st.error,
            }
            for rid, st in self._results.items()
        ]
