"""Auto Ticket Manager Agent runner — entry point."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.auto_ticket_manager.graph import (
    create_auto_ticket_manager_graph,
)
from shieldops.agents.auto_ticket_manager.models import (
    AutoTicketManagerState,
)
from shieldops.agents.auto_ticket_manager.nodes import (
    set_toolkit,
)
from shieldops.agents.auto_ticket_manager.tools import (
    AutoTicketManagerToolkit,
)

logger = structlog.get_logger()


class AutoTicketManagerRunner:
    """Runner for the Auto Ticket Manager Agent."""

    def __init__(
        self,
        jira_client: Any | None = None,
        servicenow_client: Any | None = None,
        team_router: Any | None = None,
        finding_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AutoTicketManagerToolkit(
            jira_client=jira_client,
            servicenow_client=servicenow_client,
            team_router=team_router,
            finding_store=finding_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_auto_ticket_manager_graph()
        self._app = graph.compile()
        self._results: dict[str, AutoTicketManagerState] = {}
        logger.info("auto_ticket_manager_runner.initialized")

    async def manage(
        self,
        tenant_id: str,
    ) -> AutoTicketManagerState:
        """Run ticket management workflow."""
        sid = f"tkt-{uuid4().hex[:12]}"
        initial = AutoTicketManagerState(
            tenant_id=tenant_id,
            request_id=sid,
        )

        logger.info(
            "auto_ticket_manager_runner.starting",
            session_id=sid,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": ("auto_ticket_manager"),
                    }
                },
            )
            final = AutoTicketManagerState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "auto_ticket_manager_runner.completed",
                session_id=sid,
                opened=final.tickets_opened,
                closed=final.tickets_auto_closed,
                sla_pct=final.sla_compliance_pct,
                duration_ms=(final.session_duration_ms),
            )
            return final

        except Exception as e:
            logger.error(
                "auto_ticket_manager_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err = AutoTicketManagerState(
                tenant_id=tenant_id,
                request_id=sid,
                error=str(e),
            )
            self._results[sid] = err
            return err

    def get_result(
        self,
        session_id: str,
    ) -> AutoTicketManagerState | None:
        """Retrieve a stored result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all ticket management summaries."""
        return [
            {
                "session_id": sid,
                "tenant_id": s.tenant_id,
                "opened": s.tickets_opened,
                "closed": s.tickets_auto_closed,
                "sla_pct": s.sla_compliance_pct,
                "stage": s.current_stage,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
