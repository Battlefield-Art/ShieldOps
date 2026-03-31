"""Runtime Application Protector Agent runner — entry
point for executing RASP protection sessions."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.runtime_application_protector.graph import (
    create_runtime_application_protector_graph,
)
from shieldops.agents.runtime_application_protector.models import (
    RuntimeApplicationProtectorState,
)
from shieldops.agents.runtime_application_protector.nodes import (
    set_toolkit,
)
from shieldops.agents.runtime_application_protector.tools import (
    RuntimeApplicationProtectorToolkit,
)

logger = structlog.get_logger()


class RuntimeApplicationProtectorRunner:
    """Runner for the Runtime Application Protector Agent."""

    def __init__(
        self,
        instrumenter: Any | None = None,
        runtime_monitor: Any | None = None,
        attack_detector: Any | None = None,
        classifier: Any | None = None,
        protector: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = RuntimeApplicationProtectorToolkit(
            instrumenter=instrumenter,
            runtime_monitor=runtime_monitor,
            attack_detector=attack_detector,
            classifier=classifier,
            protector=protector,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_runtime_application_protector_graph()
        self._app = graph.compile()
        self._results: dict[str, RuntimeApplicationProtectorState] = {}
        logger.info("rap_runner.initialized")

    async def protect(
        self,
        target_app: str,
        language: str = "python",
        framework: str = "fastapi",
        protection_mode: str = "enforce",
        endpoints: list[str] | None = None,
        tenant_id: str = "",
    ) -> RuntimeApplicationProtectorState:
        """Run a RASP protection session."""
        request_id = f"rap-{uuid4().hex[:12]}"

        initial_state = RuntimeApplicationProtectorState(
            request_id=request_id,
            tenant_id=tenant_id,
            target_app=target_app,
            language=language,
            framework=framework,
            protection_mode=protection_mode,
            endpoints=endpoints or [],
        )

        logger.info(
            "rap_runner.starting",
            request_id=request_id,
            app=target_app,
            language=language,
            mode=protection_mode,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "runtime_application_protector",
                    },
                },
            )
            final = RuntimeApplicationProtectorState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "rap_runner.completed",
                request_id=request_id,
                attacks_detected=final.attacks_detected,
                attacks_blocked=final.attacks_blocked,
                fp_rate=final.false_positive_rate,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "rap_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = RuntimeApplicationProtectorState(
                request_id=request_id,
                tenant_id=tenant_id,
                target_app=target_app,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> RuntimeApplicationProtectorState | None:
        """Retrieve a cached protection result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all protection results as summaries."""
        return [
            {
                "request_id": rid,
                "app": s.target_app,
                "mode": s.protection_mode,
                "attacks_detected": s.attacks_detected,
                "attacks_blocked": s.attacks_blocked,
                "fp_rate": s.false_positive_rate,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
