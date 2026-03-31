"""Attack Emulation Framework Agent runner — entry
point for adversary emulation and purple teaming."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.attack_emulation_framework.graph import (
    create_attack_emulation_framework_graph,
)
from shieldops.agents.attack_emulation_framework.models import (
    AttackEmulationState,
)
from shieldops.agents.attack_emulation_framework.nodes import (
    set_toolkit,
)
from shieldops.agents.attack_emulation_framework.tools import (
    AttackEmulationFrameworkToolkit,
)

logger = structlog.get_logger()


class AttackEmulationFrameworkRunner:
    """Runner for the Attack Emulation Framework Agent."""

    def __init__(
        self,
        mitre_library: Any | None = None,
        execution_engine: Any | None = None,
        detection_monitor: Any | None = None,
        gap_analyzer: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AttackEmulationFrameworkToolkit(
            mitre_library=mitre_library,
            execution_engine=execution_engine,
            detection_monitor=detection_monitor,
            gap_analyzer=gap_analyzer,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_attack_emulation_framework_graph()
        self._app = graph.compile()
        self._results: dict[str, AttackEmulationState] = {}
        logger.info("aef_runner.initialized")

    async def emulate(
        self,
        tenant_id: str = "",
        sector: str = "enterprise",
    ) -> AttackEmulationState:
        """Run an adversary emulation campaign."""
        request_id = f"aef-{uuid4().hex[:12]}"

        initial_state = AttackEmulationState(
            request_id=request_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "aef_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
            sector=sector,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "attack_emulation_framework",
                    },
                },
            )
            final = AttackEmulationState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "aef_runner.completed",
                request_id=request_id,
                coverage=final.detection_coverage_pct,
                executed=final.techniques_executed,
                gaps=final.gaps_found,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "aef_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = AttackEmulationState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> AttackEmulationState | None:
        """Retrieve a cached emulation result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all emulation results as summaries."""
        return [
            {
                "request_id": rid,
                "adversary": s.selected_adversary.get("name", ""),
                "coverage": s.detection_coverage_pct,
                "executed": s.techniques_executed,
                "gaps": s.gaps_found,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
