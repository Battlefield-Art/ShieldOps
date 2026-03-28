"""Tool functions for the Auto Ticket Manager Agent."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.auto_ticket_manager.models import (
    FindingTicket,
    OwnerAssignment,
    SLAStatus,
    SLATracking,
    TicketClassification,
    TicketCreation,
    TicketSystem,
)

logger = structlog.get_logger()

_SEVERITY_SLA_MAP: dict[str, int] = {
    "critical": 4,
    "high": 24,
    "medium": 72,
    "low": 168,
}

_SEVERITY_PRIORITY_MAP: dict[str, str] = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
}


class AutoTicketManagerToolkit:
    """Toolkit for automated ticket lifecycle."""

    def __init__(
        self,
        jira_client: Any | None = None,
        servicenow_client: Any | None = None,
        team_router: Any | None = None,
        finding_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._jira = jira_client
        self._servicenow = servicenow_client
        self._team_router = team_router
        self._finding_store = finding_store
        self._repository = repository

    async def receive_findings(
        self,
        tenant_id: str,
    ) -> list[FindingTicket]:
        """Receive findings to ticket."""
        logger.info(
            "auto_ticket.receive",
            tenant_id=tenant_id,
        )
        if self._finding_store is not None:
            try:
                return await self._finding_store.list(tenant_id)
            except Exception:
                logger.warning("auto_ticket.receive_fallback")
        return []

    async def classify_tickets(
        self,
        findings: list[FindingTicket],
        target_system: TicketSystem = TicketSystem.JIRA,
    ) -> list[TicketClassification]:
        """Classify findings into ticket types."""
        logger.info(
            "auto_ticket.classify",
            count=len(findings),
        )
        classifications: list[TicketClassification] = []
        for f in findings:
            sev = f.severity.lower().strip()
            classifications.append(
                TicketClassification(
                    finding_id=f.finding_id,
                    priority=_SEVERITY_PRIORITY_MAP.get(sev, "P3"),
                    ticket_type="vulnerability",
                    target_system=target_system,
                    sla_hours=_SEVERITY_SLA_MAP.get(sev, 72),
                    labels=[
                        "security",
                        f"severity:{sev}",
                    ],
                    component=f.source_agent or "unknown",
                )
            )
        return classifications

    async def create_tickets(
        self,
        classifications: list[TicketClassification],
        findings: list[FindingTicket],
    ) -> list[TicketCreation]:
        """Create tickets in target systems."""
        logger.info(
            "auto_ticket.create",
            count=len(classifications),
        )
        finding_map = {f.finding_id: f for f in findings}
        tickets: list[TicketCreation] = []
        for cls in classifications:
            finding = finding_map.get(cls.finding_id)
            title = finding.title if finding else cls.finding_id
            ticket_id = f"TKT-{uuid4().hex[:8].upper()}"

            if cls.target_system == TicketSystem.JIRA and self._jira is not None:
                try:
                    r = await self._jira.create_issue(
                        summary=title,
                        priority=cls.priority,
                        labels=cls.labels,
                    )
                    ticket_id = r.get("key", ticket_id)
                except Exception:
                    logger.warning("auto_ticket.jira_create_err")

            tickets.append(
                TicketCreation(
                    ticket_id=ticket_id,
                    finding_id=cls.finding_id,
                    system=cls.target_system,
                    external_url="",
                    priority=cls.priority,
                    status="open",
                )
            )
        return tickets

    async def assign_owners(
        self,
        tickets: list[TicketCreation],
        classifications: list[TicketClassification],
    ) -> list[OwnerAssignment]:
        """Assign owners to tickets."""
        logger.info(
            "auto_ticket.assign",
            count=len(tickets),
        )
        cls_map = {c.finding_id: c for c in classifications}
        assignments: list[OwnerAssignment] = []
        for ticket in tickets:
            cls = cls_map.get(ticket.finding_id)
            team = cls.component if cls else "security"

            if self._team_router is not None:
                try:
                    r = await self._team_router.route(team, ticket.priority)
                    assignments.append(
                        OwnerAssignment(
                            ticket_id=ticket.ticket_id,
                            assignee=r.get("assignee", ""),
                            team=r.get("team", team),
                            escalation_chain=r.get("chain", []),
                            auto_assigned=True,
                        )
                    )
                    continue
                except Exception:
                    logger.warning("auto_ticket.assign_fallback")
            assignments.append(
                OwnerAssignment(
                    ticket_id=ticket.ticket_id,
                    assignee="",
                    team=team,
                    auto_assigned=False,
                )
            )
        return assignments

    async def track_sla(
        self,
        tickets: list[TicketCreation],
        classifications: list[TicketClassification],
    ) -> list[SLATracking]:
        """Track SLA compliance for tickets."""
        logger.info(
            "auto_ticket.track_sla",
            count=len(tickets),
        )
        cls_map = {c.finding_id: c for c in classifications}
        tracking: list[SLATracking] = []
        for ticket in tickets:
            cls = cls_map.get(ticket.finding_id)
            sla_hours = cls.sla_hours if cls else 72
            tracking.append(
                SLATracking(
                    ticket_id=ticket.ticket_id,
                    finding_id=ticket.finding_id,
                    sla_hours=sla_hours,
                    elapsed_hours=0.0,
                    status=SLAStatus.WITHIN_SLA,
                )
            )
        return tracking
