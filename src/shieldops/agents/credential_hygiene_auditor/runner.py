"""Credential Hygiene Auditor Agent runner -- entry point.

Takes runtime configuration, constructs the LangGraph,
runs end-to-end, and returns completed CHA state.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.credential_hygiene_auditor.graph import (
    create_credential_hygiene_auditor_graph,
)
from shieldops.agents.credential_hygiene_auditor.models import (
    CredentialHygieneAuditorState,
)
from shieldops.agents.credential_hygiene_auditor.nodes import (
    set_toolkit,
)
from shieldops.agents.credential_hygiene_auditor.tools import (
    CredentialHygieneAuditorToolkit,
)

logger = structlog.get_logger()


class CredentialHygieneAuditorRunner:
    """Runs credential hygiene auditor workflows.

    Usage:
        runner = CredentialHygieneAuditorRunner(
            credential_store=store,
            policy_engine=engine,
        )
        result = await runner.run(tenant_id="t-123")
    """

    def __init__(
        self,
        credential_store: Any | None = None,
        policy_engine: Any | None = None,
        secret_scanner: Any | None = None,
        risk_calculator: Any | None = None,
        remediation_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CredentialHygieneAuditorToolkit(
            credential_store=credential_store,
            policy_engine=policy_engine,
            secret_scanner=secret_scanner,
            risk_calculator=risk_calculator,
            remediation_engine=remediation_engine,
            repository=repository,
        )
        # Configure module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build compiled graph
        graph = create_credential_hygiene_auditor_graph()
        self._app = graph.compile()

        # In-memory store of completed runs
        self._results: dict[str, CredentialHygieneAuditorState] = {}

    async def run(
        self,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> CredentialHygieneAuditorState:
        """Run a full credential hygiene audit cycle.

        Args:
            tenant_id: Tenant ID for scoped queries.
            config: Optional configuration overrides.

        Returns:
            Completed CredentialHygieneAuditorState.
        """
        request_id = f"cha-{uuid4().hex[:12]}"

        logger.info(
            "cha_started",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        initial_state = CredentialHygieneAuditorState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "tenant_id": tenant_id,
                    },
                },
            )

            final_state = CredentialHygieneAuditorState.model_validate(final_dict)

            # Calculate total duration
            if final_state.session_start:
                elapsed = datetime.now(UTC) - final_state.session_start
                final_state.session_duration_ms = int(elapsed.total_seconds() * 1000)

            logger.info(
                "cha_completed",
                request_id=request_id,
                credentials=final_state.credential_count,
                violations=final_state.violation_count,
                compliant=final_state.compliant_count,
                recommendations=len(final_state.recommendations),
                duration_ms=final_state.session_duration_ms,
            )

            self._results[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "cha_failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = CredentialHygieneAuditorState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> CredentialHygieneAuditorState | None:
        """Retrieve a completed run by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all runs with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": st.tenant_id,
                "stage": st.stage,
                "status": st.current_step,
                "credentials": st.credential_count,
                "violations": st.violation_count,
                "compliant": st.compliant_count,
                "recommendations": len(st.recommendations),
                "duration_ms": st.session_duration_ms,
                "error": st.error,
            }
            for rid, st in self._results.items()
        ]
