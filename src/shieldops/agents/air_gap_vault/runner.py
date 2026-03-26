"""Air-Gap Vault Agent runner — entry point for vault verification.

Takes vault parameters, constructs the LangGraph, runs it
end-to-end, and returns the completed vault state.
"""

from typing import Any

import structlog

from shieldops.agents.air_gap_vault.graph import (
    create_air_gap_vault_graph,
)
from shieldops.agents.air_gap_vault.models import AirGapVaultState
from shieldops.agents.air_gap_vault.nodes import set_toolkit
from shieldops.agents.air_gap_vault.tools import AirGapVaultToolkit
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class AirGapVaultRunner:
    """Runs air-gap vault verification workflows.

    Usage:
        runner = AirGapVaultRunner()
        result = await runner.verify(
            tenant_id="tenant-1",
            vault_id="vault-prod-01",
            scan_scope="all",
        )
    """

    def __init__(
        self,
        storage_client: Any = None,
        network_client: Any = None,
    ) -> None:
        self._toolkit = AirGapVaultToolkit(
            storage_client=storage_client,
            network_client=network_client,
        )
        set_toolkit(self._toolkit)

        graph = create_air_gap_vault_graph()
        self._app = graph.compile()

        self._verifications: dict[str, AirGapVaultState] = {}

    async def verify(
        self,
        tenant_id: str,
        vault_id: str,
        scan_scope: str = "all",
    ) -> AirGapVaultState:
        """Run a full air-gap vault verification.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            vault_id: Vault identifier to verify.
            scan_scope: Scope (all, ai_assets, backups).

        Returns:
            The completed AirGapVaultState with report.
        """
        logger.info(
            "vault_verification_started",
            tenant_id=tenant_id,
            vault_id=vault_id,
            scan_scope=scan_scope,
        )

        initial_state = AirGapVaultState(
            tenant_id=tenant_id,
            vault_id=vault_id,
            scan_scope=scan_scope,
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("air_gap_vault.verify") as span:
                span.set_attribute("vault.tenant_id", tenant_id)
                span.set_attribute("vault.vault_id", vault_id)
                span.set_attribute("vault.scan_scope", scan_scope)

                final_dict = await self._app.ainvoke(
                    initial_state.model_dump(),
                    config={
                        "metadata": {
                            "tenant_id": tenant_id,
                            "vault_id": vault_id,
                        },
                    },
                )

                final_state = AirGapVaultState.model_validate(final_dict)

                span.set_attribute(
                    "vault.duration_ms",
                    final_state.duration_ms,
                )
                span.set_attribute(
                    "vault.health_score",
                    final_state.vault_health_score,
                )
                span.set_attribute(
                    "vault.asset_count",
                    len(final_state.vault_assets),
                )
                span.set_attribute(
                    "vault.tamper_alerts",
                    len(final_state.tamper_alerts),
                )

            logger.info(
                "vault_verification_completed",
                tenant_id=tenant_id,
                vault_id=vault_id,
                duration_ms=final_state.duration_ms,
                health_score=final_state.vault_health_score,
                asset_count=len(final_state.vault_assets),
                tamper_alerts=len(final_state.tamper_alerts),
            )

            self._verifications[vault_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "vault_verification_failed",
                tenant_id=tenant_id,
                vault_id=vault_id,
                error=str(e),
            )
            error_state = AirGapVaultState(
                tenant_id=tenant_id,
                vault_id=vault_id,
                scan_scope=scan_scope,
                error=str(e),
                current_stage="failed",
            )
            return error_state

    def get_verification(self, vault_id: str) -> AirGapVaultState | None:
        """Retrieve a completed verification by vault ID."""
        return self._verifications.get(vault_id)

    def list_verifications(self) -> list[dict[str, Any]]:
        """List all verifications with summary info."""
        return [
            {
                "vault_id": vid,
                "health_score": s.vault_health_score,
                "asset_count": len(s.vault_assets),
                "tamper_alerts": len(s.tamper_alerts),
                "isolation_passed": s.isolation_passed,
                "duration_ms": s.duration_ms,
                "error": s.error,
            }
            for vid, s in self._verifications.items()
        ]
