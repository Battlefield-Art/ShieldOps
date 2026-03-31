"""Email Authentication Auditor Agent runner — entry
point for DMARC/DKIM/SPF auditing."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.email_authentication_auditor.graph import (
    create_email_authentication_auditor_graph,
)
from shieldops.agents.email_authentication_auditor.models import (
    EmailAuthenticationAuditorState,
)
from shieldops.agents.email_authentication_auditor.nodes import (
    set_toolkit,
)
from shieldops.agents.email_authentication_auditor.tools import (
    EmailAuthenticationAuditorToolkit,
)

logger = structlog.get_logger()


class EmailAuthenticationAuditorRunner:
    """Runner for the Email Authentication Auditor Agent."""

    def __init__(
        self,
        dns_resolver: Any | None = None,
        domain_registry: Any | None = None,
        dmarc_analyzer: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = EmailAuthenticationAuditorToolkit(
            dns_resolver=dns_resolver,
            domain_registry=domain_registry,
            dmarc_analyzer=dmarc_analyzer,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_email_authentication_auditor_graph()
        self._app = graph.compile()
        self._results: dict[str, EmailAuthenticationAuditorState] = {}
        logger.info("eaa_runner.initialized")

    async def audit(
        self,
        tenant_id: str = "",
        domains: list[str] | None = None,
    ) -> EmailAuthenticationAuditorState:
        """Run an email authentication audit."""
        request_id = f"eaa-{uuid4().hex[:12]}"

        initial_state = EmailAuthenticationAuditorState(
            request_id=request_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "eaa_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
            domain_count=len(domains) if domains else 0,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "email_authentication_auditor",
                    },
                },
            )
            final = EmailAuthenticationAuditorState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "eaa_runner.completed",
                request_id=request_id,
                domains=final.total_domains,
                compliant=final.domains_compliant,
                compliance=final.compliance_pct,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "eaa_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = EmailAuthenticationAuditorState(
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
    ) -> EmailAuthenticationAuditorState | None:
        """Retrieve a cached audit result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all audit results as summaries."""
        return [
            {
                "request_id": rid,
                "domains": s.total_domains,
                "compliant": s.domains_compliant,
                "compliance": s.compliance_pct,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
