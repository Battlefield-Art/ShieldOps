"""Email Security Gateway runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.email_security_gateway.graph import (
    create_email_security_gateway_graph,
)
from shieldops.agents.email_security_gateway.models import (
    EmailSecurityGatewayState,
)
from shieldops.agents.email_security_gateway.nodes import (
    set_toolkit,
)
from shieldops.agents.email_security_gateway.tools import (
    EmailSecurityGatewayToolkit,
)

logger = structlog.get_logger()


class EmailSecurityGatewayRunner:
    """Runner for the Email Security Gateway Agent."""

    def __init__(
        self,
        mail_server: Any | None = None,
        sandbox: Any | None = None,
        reputation_service: Any | None = None,
        quarantine_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = EmailSecurityGatewayToolkit(
            mail_server=mail_server,
            sandbox=sandbox,
            reputation_service=reputation_service,
            quarantine_store=quarantine_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_email_security_gateway_graph()
        self._app = graph.compile()
        self._results: dict[str, EmailSecurityGatewayState] = {}
        logger.info("esg_runner.initialized")

    async def scan(
        self,
        request_id: str,
        tenant_id: str = "",
        email_config: dict[str, Any] | None = None,
    ) -> EmailSecurityGatewayState:
        """Run email security gateway workflow."""
        sid = f"esg-{uuid4().hex[:12]}"
        initial = EmailSecurityGatewayState(
            request_id=request_id,
            tenant_id=tenant_id,
            email_config=email_config or {},
        )

        logger.info(
            "esg_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "email_security_gateway",
                    },
                },
            )
            final = EmailSecurityGatewayState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "esg_runner.completed",
                session_id=sid,
                ingested=final.total_ingested,
                auth_failures=final.auth_failure_count,
                malicious=final.malicious_attachment_count,
                quarantined=final.quarantined_count,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "esg_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = EmailSecurityGatewayState(
                request_id=request_id,
                tenant_id=tenant_id,
                email_config=email_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> EmailSecurityGatewayState | None:
        """Retrieve a previous scan result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_ingested": s.total_ingested,
                "auth_failures": s.auth_failure_count,
                "malicious_attachments": (s.malicious_attachment_count),
                "quarantined": s.quarantined_count,
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
