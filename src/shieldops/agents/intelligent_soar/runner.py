"""IntelligentSOARRunner — entry point for intelligent SOAR workflows.

Provides the `orchestrate()` method for executing
LangGraph-native playbooks with dynamic adaptation.
"""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.intelligent_soar.graph import (
    create_intelligent_soar_graph,
)
from shieldops.agents.intelligent_soar.models import (
    ExecutionMode,
    IntelligentSOARState,
    SOARTrigger,
)
from shieldops.agents.intelligent_soar.nodes import (
    set_toolkit,
)
from shieldops.agents.intelligent_soar.tools import (
    IntelligentSOARToolkit,
)

logger = structlog.get_logger()


class IntelligentSOARRunner:
    """Runner for the Intelligent SOAR Agent."""

    def __init__(
        self,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = IntelligentSOARToolkit(
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_intelligent_soar_graph()
        self._app = graph.compile()
        self._results: dict[str, IntelligentSOARState] = {}
        logger.info("intelligent_soar_runner.initialized")

    async def orchestrate(
        self,
        tenant_id: str,
        trigger: dict[str, Any] | None = None,
        execution_mode: str = (ExecutionMode.automatic),
    ) -> IntelligentSOARState:
        """Run intelligent SOAR workflow.

        Args:
            tenant_id: Tenant identifier.
            trigger: Trigger payload dict.
            execution_mode: One of automatic,
                semi_automatic, manual, dry_run.

        Returns:
            Final IntelligentSOARState.
        """
        session_id = f"isoar-{uuid4().hex[:12]}"
        trigger_data = trigger or {}
        soar_trigger = SOARTrigger(
            trigger_id=trigger_data.get(
                "trigger_id",
                f"trig-{uuid4().hex[:8]}",
            ),
            source=trigger_data.get("source", ""),
            alert_type=trigger_data.get("alert_type", "unknown"),
            severity=trigger_data.get("severity", "medium"),
            raw_payload=trigger_data,
            indicators=trigger_data.get("indicators", []),
        )

        initial_state = IntelligentSOARState(
            session_id=session_id,
            tenant_id=tenant_id,
            execution_mode=execution_mode,
            trigger=soar_trigger,
        )

        logger.info(
            "intelligent_soar_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            mode=execution_mode,
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "intelligent_soar",
                        "tenant_id": tenant_id,
                    },
                },
            )
            final_state = IntelligentSOARState.model_validate(final_dict)
            self._results[session_id] = final_state

            logger.info(
                "intelligent_soar_runner.completed",
                session_id=session_id,
                duration_ms=(final_state.session_duration_ms),
                steps=final_state.steps_completed,
                adaptations=len(final_state.adaptive_decisions),
            )
            return final_state

        except Exception as e:
            logger.error(
                "intelligent_soar_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = IntelligentSOARState(
                session_id=session_id,
                tenant_id=tenant_id,
                execution_mode=execution_mode,
                trigger=soar_trigger,
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> IntelligentSOARState | None:
        """Retrieve a past session result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all session results summary."""
        return [
            {
                "session_id": sid,
                "tenant_id": st.tenant_id,
                "current_step": st.current_step,
                "steps_completed": (st.steps_completed),
                "adaptation_rate": (st.adaptation_rate),
                "session_duration_ms": (st.session_duration_ms),
                "error": st.error,
            }
            for sid, st in self._results.items()
        ]
