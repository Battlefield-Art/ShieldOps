"""SOC Brain Agent runner — entry point for executing cross-vendor orchestration."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.soc_brain.graph import create_soc_brain_graph
from shieldops.agents.soc_brain.models import SOCBrainState, TriggerType
from shieldops.agents.soc_brain.nodes import set_toolkit
from shieldops.agents.soc_brain.tools import SOCBrainToolkit

logger = structlog.get_logger()


class SOCBrainRunner:
    """Runner for the SOC Brain Agent."""

    def __init__(
        self,
        crowdstrike_client: Any | None = None,
        defender_client: Any | None = None,
        wiz_client: Any | None = None,
        threat_intel: Any | None = None,
        mitre_mapper: Any | None = None,
        soar_engine: Any | None = None,
        policy_engine: Any | None = None,
        situation_store: Any | None = None,
        metrics_recorder: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SOCBrainToolkit(
            crowdstrike_client=crowdstrike_client,
            defender_client=defender_client,
            wiz_client=wiz_client,
            threat_intel=threat_intel,
            mitre_mapper=mitre_mapper,
            soar_engine=soar_engine,
            policy_engine=policy_engine,
            situation_store=situation_store,
            metrics_recorder=metrics_recorder,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_soc_brain_graph()
        self._app = graph.compile()
        self._results: dict[str, SOCBrainState] = {}
        self._situations: dict[str, dict[str, Any]] = {}
        logger.info("soc_brain_runner.initialized")

    async def process_alert(
        self,
        vendor: str,
        alert_data: dict[str, Any],
    ) -> SOCBrainState:
        """Process an incoming alert from a specific vendor."""
        session_id = f"brain-{uuid4().hex[:12]}"
        initial_state = SOCBrainState(
            trigger_type=TriggerType.ALERT,
            trigger_data={"vendor": vendor, "event": alert_data},
            vendor_sources=[vendor],
        )

        logger.info(
            "soc_brain_runner.process_alert",
            session_id=session_id,
            vendor=vendor,
        )

        return await self._run(session_id, initial_state)

    async def run_sweep(
        self,
        vendors: list[str] | None = None,
        time_range_minutes: int = 60,
    ) -> SOCBrainState:
        """Run a scheduled cross-vendor sweep."""
        session_id = f"brain-{uuid4().hex[:12]}"
        initial_state = SOCBrainState(
            trigger_type=TriggerType.SCHEDULED,
            trigger_data={"time_range_minutes": time_range_minutes},
            vendor_sources=vendors or ["crowdstrike", "defender", "wiz"],
        )

        logger.info(
            "soc_brain_runner.run_sweep",
            session_id=session_id,
            vendors=initial_state.vendor_sources,
            time_range_minutes=time_range_minutes,
        )

        return await self._run(session_id, initial_state)

    async def get_active_situations(self) -> list[dict[str, Any]]:
        """List open situations from all recent runs."""
        situations: list[dict[str, Any]] = []
        for state in self._results.values():
            for sit in state.situations_created:
                if sit.status not in ("closed", "remediated"):
                    situations.append(sit.model_dump())
        return situations

    async def execute_action(
        self,
        situation_id: str,
        action_id: str,
    ) -> dict[str, Any]:
        """Manually execute a recommended action."""
        for state in self._results.values():
            for action in state.recommended_actions:
                if action.action_id == action_id and action.situation_id == situation_id:
                    result = await self._toolkit.execute_containment(
                        vendor=action.vendor,
                        target=action.target,
                        action=action.description,
                    )
                    return {
                        "action_id": action_id,
                        "situation_id": situation_id,
                        "status": result.get("status", "completed"),
                        "result": result,
                    }
        return {"error": "action_not_found", "action_id": action_id}

    async def _run(
        self,
        session_id: str,
        initial_state: SOCBrainState,
    ) -> SOCBrainState:
        """Execute the SOC Brain graph workflow."""
        try:
            final_state_dict = await self._app.ainvoke(  # type: ignore[arg-type]
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={"metadata": {"session_id": session_id, "agent": "soc_brain"}},
            )
            final_state = SOCBrainState.model_validate(final_state_dict)
            self._results[session_id] = final_state

            logger.info(
                "soc_brain_runner.completed",
                session_id=session_id,
                situations=len(final_state.situations_created),
                actions_recommended=len(final_state.recommended_actions),
                actions_executed=len(final_state.executed_actions),
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error(
                "soc_brain_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = SOCBrainState(
                trigger_type=initial_state.trigger_type,
                trigger_data=initial_state.trigger_data,
                vendor_sources=initial_state.vendor_sources,
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(self, session_id: str) -> SOCBrainState | None:
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        return [
            {
                "session_id": sid,
                "trigger_type": state.trigger_type.value,
                "situations": len(state.situations_created),
                "actions_recommended": len(state.recommended_actions),
                "actions_executed": len(state.executed_actions),
                "current_step": state.current_step,
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]
