"""Node implementations for the Auto Ticket Manager Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.auto_ticket_manager.models import (
    AutoTicketManagerState,
    SLAStatus,
    TicketStage,
)
from shieldops.agents.auto_ticket_manager.prompts import (
    SYSTEM_ASSIGN,
    SYSTEM_CLASSIFY,
    SYSTEM_REPORT,
    OwnerAssignmentOutput,
    TicketClassificationOutput,
    TicketReportOutput,
)
from shieldops.agents.auto_ticket_manager.tools import (
    AutoTicketManagerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AutoTicketManagerToolkit | None = None


def set_toolkit(
    toolkit: AutoTicketManagerToolkit,
) -> None:
    """Set the global toolkit instance."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> AutoTicketManagerToolkit:
    if _toolkit is None:
        return AutoTicketManagerToolkit()
    return _toolkit


async def receive_findings(
    state: AutoTicketManagerState,
) -> dict[str, Any]:
    """Receive findings to ticket."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    findings = await toolkit.receive_findings(
        tenant_id=state.tenant_id,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "findings_received": findings,
        "current_stage": (TicketStage.RECEIVE_FINDINGS),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Received {len(findings)} findings ({elapsed}ms)",
        ],
    }


async def classify_tickets(
    state: AutoTicketManagerState,
) -> dict[str, Any]:
    """Classify findings into ticket types."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications = await toolkit.classify_tickets(
        state.findings_received,
    )

    # LLM enrichment for classification
    for cls in classifications:
        finding = next(
            (f for f in state.findings_received if f.finding_id == cls.finding_id),
            None,
        )
        if finding:
            try:
                result = await llm_structured(
                    system_prompt=SYSTEM_CLASSIFY,
                    user_prompt=(
                        f"Title: {finding.title}\n"
                        f"Severity: {finding.severity}\n"
                        f"Asset: {finding.asset}\n"
                        f"Source: {finding.source_agent}"
                    ),
                    output_schema=(TicketClassificationOutput),
                )
                cls.priority = result.priority
                cls.ticket_type = result.ticket_type
                cls.sla_hours = result.sla_hours
                cls.component = result.component
            except Exception:
                logger.warning(
                    "auto_ticket.classify_fallback",
                    finding_id=cls.finding_id,
                )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "classifications": classifications,
        "current_stage": (TicketStage.CLASSIFY_TICKETS),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Classified {len(classifications)} tickets ({elapsed}ms)",
        ],
    }


async def create_tickets(
    state: AutoTicketManagerState,
) -> dict[str, Any]:
    """Create tickets in target systems."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    tickets = await toolkit.create_tickets(
        state.classifications,
        state.findings_received,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "tickets_created": tickets,
        "tickets_opened": len(tickets),
        "current_stage": TicketStage.CREATE_TICKETS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Created {len(tickets)} tickets ({elapsed}ms)",
        ],
    }


async def assign_owners(
    state: AutoTicketManagerState,
) -> dict[str, Any]:
    """Assign owners to tickets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assignments = await toolkit.assign_owners(
        state.tickets_created,
        state.classifications,
    )

    # LLM enrichment for assignment
    for assign in assignments:
        ticket = next(
            (t for t in state.tickets_created if t.ticket_id == assign.ticket_id),
            None,
        )
        if ticket:
            try:
                result = await llm_structured(
                    system_prompt=SYSTEM_ASSIGN,
                    user_prompt=(
                        f"Ticket: {ticket.ticket_id}\n"
                        f"Priority: {ticket.priority}\n"
                        f"Team: {assign.team}"
                    ),
                    output_schema=(OwnerAssignmentOutput),
                )
                assign.assignee = result.assignee
                assign.team = result.team
                assign.escalation_chain = result.escalation_chain
                assign.auto_assigned = True
            except Exception:
                logger.warning(
                    "auto_ticket.assign_fallback",
                    ticket_id=assign.ticket_id,
                )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "assignments": assignments,
        "current_stage": TicketStage.ASSIGN_OWNERS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Assigned {len(assignments)} owners ({elapsed}ms)",
        ],
    }


async def track_sla(
    state: AutoTicketManagerState,
) -> dict[str, Any]:
    """Track SLA compliance for all tickets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sla_records = await toolkit.track_sla(
        state.tickets_created,
        state.classifications,
    )

    within = sum(1 for s in sla_records if s.status == SLAStatus.WITHIN_SLA)
    total = max(len(sla_records), 1)
    compliance = round((within / total) * 100, 1)

    auto_closed = sum(1 for s in sla_records if s.auto_closed)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "sla_status": sla_records,
        "sla_compliance_pct": compliance,
        "tickets_auto_closed": auto_closed,
        "current_stage": TicketStage.TRACK_SLA,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"SLA compliance: {compliance}%, {auto_closed} auto-closed ({elapsed}ms)",
        ],
    }


async def generate_report(
    state: AutoTicketManagerState,
) -> dict[str, Any]:
    """Generate ticket management report."""
    start = datetime.now(UTC)

    try:
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(
                f"Tickets created: "
                f"{state.tickets_opened}\n"
                f"Auto-closed: "
                f"{state.tickets_auto_closed}\n"
                f"SLA compliance: "
                f"{state.sla_compliance_pct}%\n"
                f"Findings received: "
                f"{len(state.findings_received)}"
            ),
            output_schema=TicketReportOutput,
        )
        summary = result.executive_summary
    except Exception:
        logger.warning("auto_ticket.report_fallback")
        summary = (
            f"Created {state.tickets_opened} tickets, SLA compliance {state.sla_compliance_pct}%"
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "current_stage": TicketStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Report: {summary[:100]} ({elapsed}ms)",
        ],
        "session_duration_ms": (state.session_duration_ms + elapsed),
    }
