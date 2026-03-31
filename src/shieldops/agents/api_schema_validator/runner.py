"""API Schema Validator runner -- entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.api_schema_validator.graph import (
    create_api_schema_validator_graph,
)
from shieldops.agents.api_schema_validator.models import (
    APISchemaValidatorState,
)
from shieldops.agents.api_schema_validator.nodes import (
    set_toolkit,
)
from shieldops.agents.api_schema_validator.tools import (
    APISchemaValidatorToolkit,
)

logger = structlog.get_logger()


class APISchemaValidatorRunner:
    """Runner for the API Schema Validator Agent."""

    def __init__(
        self,
        schema_registry: Any | None = None,
        api_gateway: Any | None = None,
        contract_engine: Any | None = None,
        diff_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = APISchemaValidatorToolkit(
            schema_registry=schema_registry,
            api_gateway=api_gateway,
            contract_engine=contract_engine,
            diff_engine=diff_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_api_schema_validator_graph()
        self._app = graph.compile()
        self._results: dict[str, APISchemaValidatorState] = {}
        logger.info("asv_runner.initialized")

    async def validate(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> APISchemaValidatorState:
        """Run API schema validation workflow."""
        sid = f"asv-{uuid4().hex[:12]}"
        initial = APISchemaValidatorState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "asv_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "api_schema_validator",
                    },
                },
            )
            final = APISchemaValidatorState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "asv_runner.completed",
                session_id=sid,
                schemas=len(final.discovered_schemas),
                violations=final.violation_count,
                breaking=len(final.breaking_changes),
                fixes=len(final.suggested_fixes),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "asv_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = APISchemaValidatorState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> APISchemaValidatorState | None:
        """Retrieve a previous validation result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all validation results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_schemas": len(s.discovered_schemas),
                "violations": s.violation_count,
                "breaking_changes": len(s.breaking_changes),
                "critical_breaking": s.critical_breaking_count,
                "fixes": len(s.suggested_fixes),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
