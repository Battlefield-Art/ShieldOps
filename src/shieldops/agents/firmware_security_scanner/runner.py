"""Firmware Security Scanner runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.firmware_security_scanner.graph import (
    create_firmware_security_scanner_graph,
)
from shieldops.agents.firmware_security_scanner.models import (
    FirmwareSecurityScannerState,
)
from shieldops.agents.firmware_security_scanner.nodes import (
    set_toolkit,
)
from shieldops.agents.firmware_security_scanner.tools import (
    FirmwareSecurityScannerToolkit,
)

logger = structlog.get_logger()


class FirmwareSecurityScannerRunner:
    """Runner for the Firmware Security Scanner Agent."""

    def __init__(
        self,
        binary_analyzer: Any | None = None,
        cve_database: Any | None = None,
        crypto_scanner: Any | None = None,
        sbom_generator: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = FirmwareSecurityScannerToolkit(
            binary_analyzer=binary_analyzer,
            cve_database=cve_database,
            crypto_scanner=crypto_scanner,
            sbom_generator=sbom_generator,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_firmware_security_scanner_graph()
        self._app = graph.compile()
        self._results: dict[str, FirmwareSecurityScannerState] = {}
        logger.info("fss_runner.initialized")

    async def scan(
        self,
        request_id: str,
        tenant_id: str = "",
        scan_config: dict[str, Any] | None = None,
    ) -> FirmwareSecurityScannerState:
        """Run firmware security scanning workflow."""
        sid = f"fss-{uuid4().hex[:12]}"
        initial = FirmwareSecurityScannerState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_config=scan_config or {},
        )

        logger.info(
            "fss_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "firmware_security_scanner",
                    },
                },
            )
            final = FirmwareSecurityScannerState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "fss_runner.completed",
                session_id=sid,
                images=final.total_extracted,
                components=len(final.components),
                vulns=len(final.vulnerabilities),
                critical=final.critical_vuln_count,
                weak_crypto=final.weak_crypto_count,
                max_risk=final.max_risk_score,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "fss_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = FirmwareSecurityScannerState(
                request_id=request_id,
                tenant_id=tenant_id,
                scan_config=scan_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> FirmwareSecurityScannerState | None:
        """Retrieve a previous scan result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_images": s.total_extracted,
                "components": len(s.components),
                "vulnerabilities": len(s.vulnerabilities),
                "critical_vulns": s.critical_vuln_count,
                "weak_crypto": s.weak_crypto_count,
                "max_risk": s.max_risk_score,
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
