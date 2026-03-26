"""Ransomware Forensics Agent runner — entry point for investigations."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ransomware_forensics.graph import (
    create_ransomware_forensics_graph,
)
from shieldops.agents.ransomware_forensics.models import (
    RansomwareForensicsState,
)
from shieldops.agents.ransomware_forensics.nodes import (
    set_toolkit,
)
from shieldops.agents.ransomware_forensics.tools import (
    RansomwareForensicsToolkit,
)

logger = structlog.get_logger()


class RansomwareForensicsRunner:
    """Runner for the Ransomware Forensics Agent."""

    def __init__(
        self,
        edr_connector: Any | None = None,
        backup_connector: Any | None = None,
        threat_intel_feed: Any | None = None,
        network_sensor: Any | None = None,
        identity_provider: Any | None = None,
        cloud_connector: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = RansomwareForensicsToolkit(
            edr_connector=edr_connector,
            backup_connector=backup_connector,
            threat_intel_feed=threat_intel_feed,
            network_sensor=network_sensor,
            identity_provider=identity_provider,
            cloud_connector=cloud_connector,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_ransomware_forensics_graph()
        self._app = graph.compile()
        self._results: dict[str, RansomwareForensicsState] = {}
        logger.info("ransomware_forensics_runner.initialized")

    async def investigate(
        self,
        tenant_id: str,
        incident_id: str,
        target_systems: list[str] | None = None,
    ) -> RansomwareForensicsState:
        """Run a ransomware forensic investigation.

        Args:
            tenant_id: Tenant identifier.
            incident_id: Incident to investigate.
            target_systems: Systems to analyze.

        Returns:
            Final investigation state with findings.
        """
        session_id = f"ransomware-forensics-{uuid4().hex[:12]}"
        initial_state = RansomwareForensicsState(
            tenant_id=tenant_id,
            incident_id=incident_id,
            target_systems=target_systems or [],
        )

        logger.info(
            "ransomware_forensics_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            system_count=len(initial_state.target_systems),
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "ransomware_forensics",
                    }
                },
            )
            final_state = RansomwareForensicsState.model_validate(final_dict)
            self._results[session_id] = final_state

            logger.info(
                "ransomware_forensics_runner.completed",
                session_id=session_id,
                variant=final_state.variant_identified.get("variant", "unknown"),
                blast_level=final_state.blast_radius.get("level", "unknown"),
                affected=final_state.affected_systems_count,
                encrypted_gb=(final_state.estimated_data_encrypted_gb),
                duration_ms=(final_state.session_duration_ms),
            )
            return final_state

        except Exception as e:
            logger.error(
                "ransomware_forensics_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = RansomwareForensicsState(
                tenant_id=tenant_id,
                incident_id=incident_id,
                target_systems=target_systems or [],
                error=str(e),
                current_stage="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(self, session_id: str) -> RansomwareForensicsState | None:
        """Retrieve a past investigation result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all investigation results."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "incident_id": state.incident_id,
                "variant": (state.variant_identified.get("variant", "unknown")),
                "blast_level": (state.blast_radius.get("level", "unknown")),
                "affected_systems": (state.affected_systems_count),
                "encrypted_gb": (state.estimated_data_encrypted_gb),
                "current_stage": state.current_stage,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]
