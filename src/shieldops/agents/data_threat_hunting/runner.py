"""Data Threat Hunting Agent runner — entry point for hunt campaigns."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.data_threat_hunting.graph import (
    create_data_threat_hunting_graph,
)
from shieldops.agents.data_threat_hunting.models import (
    DataThreatHuntingState,
    HuntSource,
)
from shieldops.agents.data_threat_hunting.nodes import (
    set_toolkit,
)
from shieldops.agents.data_threat_hunting.policy import (
    check_hunt_policy,
)
from shieldops.agents.data_threat_hunting.tools import (
    DataThreatHuntingToolkit,
)

logger = structlog.get_logger()


class DataThreatHuntingRunner:
    """Runner for the Data Threat Hunting Agent."""

    def __init__(
        self,
        threat_intel: Any | None = None,
        ioc_scanner: Any | None = None,
        backup_connector: Any | None = None,
        ai_pipeline_connector: Any | None = None,
        cloud_storage_connector: Any | None = None,
        database_connector: Any | None = None,
        mitre_mapper: Any | None = None,
        signal_correlator: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
        opa_endpoint: str | None = None,
    ) -> None:
        self._toolkit = DataThreatHuntingToolkit(
            threat_intel=threat_intel,
            ioc_scanner=ioc_scanner,
            backup_connector=backup_connector,
            ai_pipeline_connector=ai_pipeline_connector,
            cloud_storage_connector=cloud_storage_connector,
            database_connector=database_connector,
            mitre_mapper=mitre_mapper,
            signal_correlator=signal_correlator,
            policy_engine=policy_engine,
            repository=repository,
        )
        self._opa_endpoint = opa_endpoint
        set_toolkit(self._toolkit)
        graph = create_data_threat_hunting_graph()
        self._app = graph.compile()
        self._results: dict[str, DataThreatHuntingState] = {}
        logger.info("data_threat_hunting_runner.initialized")

    async def hunt(
        self,
        tenant_id: str,
        hypotheses: list[str] | None = None,
        target_sources: list[str] | None = None,
        hunt_scope: dict[str, Any] | None = None,
    ) -> DataThreatHuntingState:
        """Run a data threat hunting campaign.

        Args:
            tenant_id: Tenant identifier.
            hypotheses: Initial hunt hypotheses.
            target_sources: Data sources to hunt in.
            hunt_scope: Additional scope configuration.

        Returns:
            Final DataThreatHuntingState with results.
        """
        hunt_id = f"dth-{uuid4().hex[:12]}"
        scope = hunt_scope or {}
        sources = target_sources or [
            HuntSource.production,
            HuntSource.backup_snapshot,
        ]

        # Policy check before hunting
        policy_result = await check_hunt_policy(
            tenant_id=tenant_id,
            hunt_scope=scope,
            opa_endpoint=self._opa_endpoint,
        )
        if not policy_result.get("allowed", False):
            reason = policy_result.get("reason", "Policy denied")
            logger.warning(
                "data_threat_hunting_runner.denied",
                hunt_id=hunt_id,
                tenant_id=tenant_id,
                reason=reason,
            )
            return DataThreatHuntingState(
                tenant_id=tenant_id,
                hunt_id=hunt_id,
                error=f"Policy denied: {reason}",
                current_step="failed",
            )

        initial_state = DataThreatHuntingState(
            tenant_id=tenant_id,
            hunt_id=hunt_id,
            initial_hypotheses=hypotheses or [],
            target_sources=sources,
            hunt_scope=scope,
        )

        logger.info(
            "data_threat_hunting_runner.starting",
            hunt_id=hunt_id,
            tenant_id=tenant_id,
            hypothesis_count=len(initial_state.initial_hypotheses),
            sources=sources,
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "hunt_id": hunt_id,
                        "agent": "data_threat_hunting",
                        "tenant_id": tenant_id,
                    }
                },
            )
            final_state = DataThreatHuntingState.model_validate(final_dict)
            self._results[hunt_id] = final_state

            logger.info(
                "data_threat_hunting_runner.completed",
                hunt_id=hunt_id,
                threats_confirmed=(final_state.threats_confirmed),
                findings=len(final_state.findings),
                duration_s=(final_state.hunt_duration_seconds),
            )
            return final_state

        except Exception as e:
            logger.error(
                "data_threat_hunting_runner.failed",
                hunt_id=hunt_id,
                error=str(e),
            )
            error_state = DataThreatHuntingState(
                tenant_id=tenant_id,
                hunt_id=hunt_id,
                error=str(e),
                current_step="failed",
            )
            self._results[hunt_id] = error_state
            return error_state

    def get_result(self, hunt_id: str) -> DataThreatHuntingState | None:
        """Get a previous hunt result by ID."""
        return self._results.get(hunt_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all hunt results with summary info."""
        return [
            {
                "hunt_id": hid,
                "tenant_id": state.tenant_id,
                "threats_confirmed": (state.threats_confirmed),
                "findings_count": len(state.findings),
                "hypotheses_count": len(state.hypotheses),
                "duration_s": (state.hunt_duration_seconds),
                "current_step": state.current_step,
                "error": state.error,
            }
            for hid, state in self._results.items()
        ]
