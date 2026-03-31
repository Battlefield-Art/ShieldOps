"""Compliance Questionnaire Engine Agent runner — entry
point for automated questionnaire processing."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.compliance_questionnaire_engine.graph import (
    create_compliance_questionnaire_engine_graph,
)
from shieldops.agents.compliance_questionnaire_engine.models import (
    ComplianceQuestionnaireEngineState,
    FrameworkType,
)
from shieldops.agents.compliance_questionnaire_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.compliance_questionnaire_engine.tools import (
    ComplianceQuestionnaireEngineToolkit,
)

logger = structlog.get_logger()


class ComplianceQuestionnaireEngineRunner:
    """Runner for the Compliance Questionnaire Engine Agent."""

    def __init__(
        self,
        questionnaire_parser: Any | None = None,
        control_registry: Any | None = None,
        evidence_store: Any | None = None,
        answer_library: Any | None = None,
        gap_analyzer: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ComplianceQuestionnaireEngineToolkit(
            questionnaire_parser=questionnaire_parser,
            control_registry=control_registry,
            evidence_store=evidence_store,
            answer_library=answer_library,
            gap_analyzer=gap_analyzer,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_compliance_questionnaire_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, ComplianceQuestionnaireEngineState] = {}
        logger.info("cqe_runner.initialized")

    async def process_questionnaire(
        self,
        questionnaire_name: str,
        framework: str = "soc2",
        vendor_name: str = "",
        questions: list[dict[str, Any]] | None = None,
        due_date: str = "",
        tenant_id: str = "",
    ) -> ComplianceQuestionnaireEngineState:
        """Process a compliance questionnaire end-to-end."""
        request_id = f"cqe-{uuid4().hex[:12]}"

        initial_state = ComplianceQuestionnaireEngineState(
            request_id=request_id,
            tenant_id=tenant_id,
            questionnaire_name=questionnaire_name,
            framework=FrameworkType(framework),
            vendor_name=vendor_name,
            questions=questions or [],
            due_date=due_date,
        )

        logger.info(
            "cqe_runner.starting",
            request_id=request_id,
            questionnaire=questionnaire_name,
            framework=framework,
            questions=len(questions or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("compliance_questionnaire_engine"),
                    },
                },
            )
            final = ComplianceQuestionnaireEngineState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "cqe_runner.completed",
                request_id=request_id,
                answered=final.answered_count,
                gaps=final.gap_count,
                coverage=final.coverage_score,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "cqe_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = ComplianceQuestionnaireEngineState(
                request_id=request_id,
                tenant_id=tenant_id,
                questionnaire_name=questionnaire_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> ComplianceQuestionnaireEngineState | None:
        """Retrieve a cached questionnaire result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all questionnaire results as summaries."""
        return [
            {
                "request_id": rid,
                "questionnaire": s.questionnaire_name,
                "framework": s.framework.value,
                "answered": s.answered_count,
                "gaps": s.gap_count,
                "coverage": s.coverage_score,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
