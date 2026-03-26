"""SOC Transformation Agent runner — entry point for execution."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.soc_transformation.graph import (
    create_soc_transformation_graph,
)
from shieldops.agents.soc_transformation.models import (
    MigrationTarget,
    SOCMaturity,
    SOCTransformationState,
)
from shieldops.agents.soc_transformation.nodes import (
    set_toolkit,
)
from shieldops.agents.soc_transformation.tools import (
    SOCTransformationToolkit,
)

logger = structlog.get_logger()


class SOCTransformationRunner:
    """Runner for the SOC Transformation Agent."""

    def __init__(
        self,
        splunk_client: Any | None = None,
        elastic_client: Any | None = None,
        siem_client: Any | None = None,
        otel_manager: Any | None = None,
        detection_store: Any | None = None,
        playbook_store: Any | None = None,
        metrics_recorder: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SOCTransformationToolkit(
            splunk_client=splunk_client,
            elastic_client=elastic_client,
            siem_client=siem_client,
            otel_manager=otel_manager,
            detection_store=detection_store,
            playbook_store=playbook_store,
            metrics_recorder=metrics_recorder,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_soc_transformation_graph()
        self._app = graph.compile()
        self._results: dict[str, SOCTransformationState] = {}
        logger.info("soc_transformation_runner.initialized")

    async def transform(
        self,
        tenant_id: str,
        target_maturity: str = "adaptive",
        scope: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> SOCTransformationState:
        """Run a full SOC transformation workflow.

        Args:
            tenant_id: Tenant identifier.
            target_maturity: Target SOC maturity level.
            scope: Migration targets to include. Defaults
                to all five categories.
            config: Additional configuration overrides.

        Returns:
            Final SOCTransformationState with results.
        """
        session_id = f"transform-{uuid4().hex[:12]}"

        # Parse maturity
        maturity = SOCMaturity.ADAPTIVE
        if target_maturity in [m.value for m in SOCMaturity]:
            maturity = SOCMaturity(target_maturity)

        # Parse scope
        targets: list[MigrationTarget] = []
        if scope:
            for s in scope:
                if s in [t.value for t in MigrationTarget]:
                    targets.append(MigrationTarget(s))
        if not targets:
            targets = list(MigrationTarget)

        initial_state = SOCTransformationState(
            tenant_id=tenant_id,
            target_maturity=maturity,
            transformation_scope=targets,
            config=config or {},
        )

        logger.info(
            "soc_transformation_runner.transform",
            session_id=session_id,
            tenant_id=tenant_id,
            target_maturity=maturity.value,
            scope=[t.value for t in targets],
        )

        return await self._run(session_id, initial_state)

    async def assess_only(
        self,
        tenant_id: str,
    ) -> SOCTransformationState:
        """Run assessment only (no migration).

        Useful for generating a maturity report before
        committing to a full transformation.
        """
        session_id = f"assess-{uuid4().hex[:12]}"
        initial_state = SOCTransformationState(
            tenant_id=tenant_id,
            transformation_scope=[],
        )

        logger.info(
            "soc_transformation_runner.assess_only",
            session_id=session_id,
            tenant_id=tenant_id,
        )

        return await self._run(session_id, initial_state)

    async def _run(
        self,
        session_id: str,
        initial_state: SOCTransformationState,
    ) -> SOCTransformationState:
        """Execute the SOC transformation graph."""
        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "soc_transformation",
                    },
                },
            )
            final_state = SOCTransformationState.model_validate(
                final_dict,
            )
            self._results[session_id] = final_state

            logger.info(
                "soc_transformation_runner.completed",
                session_id=session_id,
                maturity=(
                    f"{final_state.current_maturity.value}->{final_state.target_maturity.value}"
                ),
                steps_completed=final_state.steps_completed,
                rules_migrated=(final_state.detection_rules_migrated),
                sources_connected=(final_state.data_sources_connected),
                validation_passed=(final_state.validation_passed),
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error(
                "soc_transformation_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = SOCTransformationState(
                tenant_id=initial_state.tenant_id,
                transformation_scope=(initial_state.transformation_scope),
                error=str(e),
                current_stage="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> SOCTransformationState | None:
        """Retrieve a past transformation result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all transformation results."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "current_maturity": (state.current_maturity.value),
                "target_maturity": (state.target_maturity.value),
                "steps_completed": state.steps_completed,
                "rules_migrated": (state.detection_rules_migrated),
                "sources_connected": (state.data_sources_connected),
                "validation_passed": (state.validation_passed),
                "current_stage": state.current_stage,
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]
