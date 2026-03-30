"""Cloud Secret Vault runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cloud_secret_vault.graph import (
    create_cloud_secret_vault_graph,
)
from shieldops.agents.cloud_secret_vault.models import (
    CloudSecretVaultState,
)
from shieldops.agents.cloud_secret_vault.nodes import (
    set_toolkit,
)
from shieldops.agents.cloud_secret_vault.tools import (
    CloudSecretVaultToolkit,
)

logger = structlog.get_logger()


class CloudSecretVaultRunner:
    """Runner for the Cloud Secret Vault Agent."""

    def __init__(
        self,
        vault_client: Any | None = None,
        code_scanner: Any | None = None,
        breach_monitor: Any | None = None,
        rotation_engine: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudSecretVaultToolkit(
            vault_client=vault_client,
            code_scanner=code_scanner,
            breach_monitor=breach_monitor,
            rotation_engine=rotation_engine,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cloud_secret_vault_graph()
        self._app = graph.compile()
        self._results: dict[str, CloudSecretVaultState] = {}
        logger.info("vault_runner.initialized")

    async def scan(
        self,
        request_id: str,
        tenant_id: str = "",
        scan_config: dict[str, Any] | None = None,
    ) -> CloudSecretVaultState:
        """Run cloud secret vault scanning workflow."""
        sid = f"vault-{uuid4().hex[:12]}"
        initial = CloudSecretVaultState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_config=scan_config or {},
        )

        logger.info(
            "vault_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "cloud_secret_vault",
                    },
                },
            )
            final = CloudSecretVaultState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "vault_runner.completed",
                session_id=sid,
                secrets=len(final.discovered_secrets),
                unmanaged=final.unmanaged_count,
                overdue=final.overdue_count,
                exposed=final.exposed_count,
                risk=final.max_risk_score,
                remediations=len(final.remediations),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "vault_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = CloudSecretVaultState(
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
    ) -> CloudSecretVaultState | None:
        """Retrieve a previous scan result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_secrets": len(s.discovered_secrets),
                "unmanaged": s.unmanaged_count,
                "overdue": s.overdue_count,
                "exposed": s.exposed_count,
                "max_risk": s.max_risk_score,
                "remediations": len(s.remediations),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
