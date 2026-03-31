"""Security Ticket Automator Agent runner — entry point
for executing automated ticket creation workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_ticket_automator.graph import (
    create_security_ticket_automator_graph,
)
from shieldops.agents.security_ticket_automator.models import (
    SecurityTicketAutomatorState,
    TicketPlatform,
)
from shieldops.agents.security_ticket_automator.nodes import (
    set_toolkit,
)
from shieldops.agents.security_ticket_automator.tools import (
    SecurityTicketAutomatorToolkit,
)

logger = structlog.get_logger()


class SecurityTicketAutomatorRunner:
    """Runner for the Security Ticket Automator Agent."""

    def __init__(
        self,
        ticket_client: Any | None = None,
        threat_intel: Any | None = None,
        asset_inventory: Any | None = None,
        sla_engine: Any | None = None,
        escalation_engine: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityTicketAutomatorToolkit(
            ticket_client=ticket_client,
            threat_intel=threat_intel,
            asset_inventory=asset_inventory,
            sla_engine=sla_engine,
            escalation_engine=escalation_engine,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_ticket_automator_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityTicketAutomatorState] = {}
        logger.info("sta_runner.initialized")

    async def automate(
        self,
        source_system: str,
        platform: str = "jira",
        auto_assign: bool = True,
        escalation_rules: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> SecurityTicketAutomatorState:
        """Run automated security ticket creation."""
        request_id = f"sta-{uuid4().hex[:12]}"

        initial_state = SecurityTicketAutomatorState(
            request_id=request_id,
            tenant_id=tenant_id,
            source_system=source_system,
            platform=TicketPlatform(platform),
            auto_assign=auto_assign,
            escalation_rules=escalation_rules or {},
        )

        logger.info(
            "sta_runner.starting",
            request_id=request_id,
            source=source_system,
            platform=platform,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "security_ticket_automator",
                    },
                },
            )
            final = SecurityTicketAutomatorState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "sta_runner.completed",
                request_id=request_id,
                total_issues=final.total_issues,
                tickets_created=final.tickets_created,
                sla_compliant=final.sla_compliant_count,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "sta_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityTicketAutomatorState(
                request_id=request_id,
                tenant_id=tenant_id,
                source_system=source_system,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> SecurityTicketAutomatorState | None:
        """Retrieve a cached automation result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all automation results as summaries."""
        return [
            {
                "request_id": rid,
                "source": s.source_system,
                "platform": s.platform.value,
                "total_issues": s.total_issues,
                "tickets_created": s.tickets_created,
                "sla_compliant": s.sla_compliant_count,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
