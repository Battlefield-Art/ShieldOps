"""Threat Scenario Runner Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_scenario_runner.graph import (
    create_threat_scenario_runner_graph,
)
from shieldops.agents.threat_scenario_runner.models import (
    ScenarioCategory,
    ThreatScenario,
    ThreatScenarioRunnerState,
)
from shieldops.agents.threat_scenario_runner.nodes import (
    set_toolkit,
)
from shieldops.agents.threat_scenario_runner.tools import (
    ThreatScenarioRunnerToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class ThreatScenarioRunnerRunner:
    """Runs threat scenario regression tests.

    Usage::

        runner = ThreatScenarioRunnerRunner()
        result = await runner.run_scenario(
            tenant_id="acme",
            scenario="ransomware_readiness",
        )
    """

    def __init__(
        self,
        scenario_store: Any | None = None,
        control_monitor: Any | None = None,
        environment_mgr: Any | None = None,
    ) -> None:
        self._toolkit = ThreatScenarioRunnerToolkit(
            scenario_store=scenario_store,
            control_monitor=control_monitor,
            environment_mgr=environment_mgr,
        )
        set_toolkit(self._toolkit)

        graph = create_threat_scenario_runner_graph()
        self._app = graph.compile()
        self._runs: dict[str, ThreatScenarioRunnerState] = {}

    async def run_scenario(
        self,
        tenant_id: str,
        scenario: str = "ransomware_readiness",
        description: str = "",
        context: dict[str, Any] | None = None,
    ) -> ThreatScenarioRunnerState:
        """Run a threat scenario.

        Args:
            tenant_id: Tenant identifier.
            scenario: Scenario category name.
            description: Optional description.
            context: Optional overrides.

        Returns:
            Completed state with verdict.
        """
        request_id = f"tsr-{uuid4().hex[:12]}"

        logger.info(
            "scenario_runner_started",
            request_id=request_id,
            tenant_id=tenant_id,
            scenario=scenario,
        )

        category = ScenarioCategory(scenario)
        initial = ThreatScenarioRunnerState(
            request_id=request_id,
            tenant_id=tenant_id,
            scenario=ThreatScenario(
                category=category,
                description=description,
            ),
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("scenario_runner.run_scenario") as span:
                span.set_attribute(
                    "scenario_runner.request_id",
                    request_id,
                )
                span.set_attribute(
                    "scenario_runner.tenant_id",
                    tenant_id,
                )
                span.set_attribute(
                    "scenario_runner.category",
                    scenario,
                )

                final_dict = await self._app.ainvoke(
                    initial.model_dump(),
                    config={
                        "metadata": {
                            "request_id": request_id,
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final = ThreatScenarioRunnerState.model_validate(final_dict)

                span.set_attribute(
                    "scenario_runner.verdict",
                    final.verdict.verdict.value,
                )

            logger.info(
                "scenario_runner_completed",
                request_id=request_id,
                verdict=final.verdict.verdict,
                score=final.verdict.score,
                duration_ms=final.session_duration_ms,
            )

            self._runs[request_id] = final
            return final

        except Exception as e:
            logger.error(
                "scenario_runner_failed",
                request_id=request_id,
                error=str(e),
            )
            err = ThreatScenarioRunnerState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._runs[request_id] = err
            return err

    def get_run(
        self,
        request_id: str,
    ) -> ThreatScenarioRunnerState | None:
        """Retrieve a completed run."""
        return self._runs.get(request_id)

    def list_runs(self) -> list[dict[str, Any]]:
        """List all scenario runs."""
        return [
            {
                "request_id": rid,
                "tenant_id": s.tenant_id,
                "scenario": s.scenario.name,
                "status": s.current_step,
                "verdict": s.verdict.verdict,
                "score": s.verdict.score,
                "passed": s.controls_passed,
                "failed": s.controls_failed,
                "duration_ms": s.session_duration_ms,
                "error": s.error,
            }
            for rid, s in self._runs.items()
        ]
