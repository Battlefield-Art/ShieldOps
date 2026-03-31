"""Data Privacy Scanner Agent runner — entry point for
executing PII/PHI/PCI discovery scans."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.data_privacy_scanner.graph import (
    create_data_privacy_scanner_graph,
)
from shieldops.agents.data_privacy_scanner.models import (
    ComplianceRegime,
    DataPrivacyScannerState,
)
from shieldops.agents.data_privacy_scanner.nodes import (
    set_toolkit,
)
from shieldops.agents.data_privacy_scanner.tools import (
    DataPrivacyScannerToolkit,
)

logger = structlog.get_logger()


class DataPrivacyScannerRunner:
    """Runner for the Data Privacy Scanner Agent."""

    def __init__(
        self,
        datastore_client: Any | None = None,
        classifier: Any | None = None,
        pii_detector: Any | None = None,
        flow_mapper: Any | None = None,
        compliance_engine: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DataPrivacyScannerToolkit(
            datastore_client=datastore_client,
            classifier=classifier,
            pii_detector=pii_detector,
            flow_mapper=flow_mapper,
            compliance_engine=compliance_engine,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_data_privacy_scanner_graph()
        self._app = graph.compile()
        self._results: dict[str, DataPrivacyScannerState] = {}
        logger.info("dps_runner.initialized")

    async def scan(
        self,
        scan_name: str,
        target_datastores: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        regimes: list[str] | None = None,
        tenant_id: str = "",
    ) -> DataPrivacyScannerState:
        """Run a data privacy scan."""
        request_id = f"dps-{uuid4().hex[:12]}"

        regime_list = [
            ComplianceRegime(r)
            for r in (regimes or [])
            if r in ComplianceRegime.__members__.values()
        ]

        initial_state = DataPrivacyScannerState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_name=scan_name,
            target_datastores=target_datastores or [],
            scope=scope or {},
            regimes=regime_list,
        )

        logger.info(
            "dps_runner.starting",
            request_id=request_id,
            scan_name=scan_name,
            datastores=len(target_datastores or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "data_privacy_scanner",
                    },
                },
            )
            final = DataPrivacyScannerState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "dps_runner.completed",
                request_id=request_id,
                total_datastores=final.total_datastores,
                pii=final.pii_count,
                phi=final.phi_count,
                pci=final.pci_count,
                score=final.compliance_score,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "dps_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = DataPrivacyScannerState(
                request_id=request_id,
                tenant_id=tenant_id,
                scan_name=scan_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> DataPrivacyScannerState | None:
        """Retrieve a cached scan result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results as summaries."""
        return [
            {
                "request_id": rid,
                "scan_name": s.scan_name,
                "total_datastores": s.total_datastores,
                "pii": s.pii_count,
                "phi": s.phi_count,
                "pci": s.pci_count,
                "score": s.compliance_score,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
