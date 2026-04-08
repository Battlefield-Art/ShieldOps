"""Node implementations for the Security Ticket Automator
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_ticket_automator.models import (
    ReasoningStep,
    SecurityTicketAutomatorState,
    STAStage,
)
from shieldops.agents.security_ticket_automator.prompts import (
    SYSTEM_ASSIGN,
    SYSTEM_DETECT,
    SYSTEM_ENRICH,
    SYSTEM_REPORT,
    ContextEnrichmentOutput,
    IssueDetectionOutput,
    OwnerAssignmentOutput,
    TicketReportOutput,
)
from shieldops.agents.security_ticket_automator.tools import (
    SecurityTicketAutomatorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityTicketAutomatorToolkit | None = None


def _get_toolkit() -> SecurityTicketAutomatorToolkit:
    if _toolkit is None:
        return SecurityTicketAutomatorToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: datetime,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: detect_issue
# ------------------------------------------------------------------


async def detect_issue(
    state: SecurityTicketAutomatorState,
) -> dict[str, Any]:
    """Detect security issues from source telemetry
    and alert feeds."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.detect_issues(
        source_system=state.source_system,
        scope=state.escalation_rules,
    )

    issues: list[dict[str, Any]] = list(results)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "source": state.source_system,
                "platform": state.platform.value,
                "escalation_rules": state.escalation_rules,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DETECT,
            user_prompt=f"Detect security issues:\n{ctx}",
            schema=IssueDetectionOutput,
        )
        if llm_out.issues:  # type: ignore[union-attr]
            issues = [
                *issues,
                *llm_out.issues,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="detect_issue",
            count=len(llm_out.issues),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_issue",
        )

    step = _step(
        state.reasoning_chain,
        "detect_issue",
        f"Source: {state.source_system}, platform={state.platform}",
        f"Detected {len(issues)} issues",
        start,
        "issue_detector",
    )

    return {
        "issues": issues,
        "total_issues": len(issues),
        "stage": STAStage.DETECT_ISSUE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_issue",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: enrich_context
# ------------------------------------------------------------------


async def enrich_context(
    state: SecurityTicketAutomatorState,
) -> dict[str, Any]:
    """Enrich detected issues with threat intelligence
    and asset context."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    enrichments = await toolkit.enrich_context(
        issues=state.issues,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "issues": state.issues[:5],
                "issue_count": len(state.issues),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ENRICH,
            user_prompt=f"Enrich issue context:\n{ctx}",
            schema=ContextEnrichmentOutput,
        )
        rid = random.randint(1000, 9999)  # noqa: S311
        if llm_out.threat_context:  # type: ignore[union-attr]
            enrichments.append(
                {
                    "enrichment_id": f"llm-{rid}",
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "related_cves": llm_out.related_cves,  # type: ignore[union-attr]
                    "threat_context": llm_out.threat_context,  # type: ignore[union-attr]
                    "recommended_priority": llm_out.recommended_priority,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="enrich_context",
            cves=len(llm_out.related_cves),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enrich_context",
        )

    step = _step(
        state.reasoning_chain,
        "enrich_context",
        f"Enriching {len(state.issues)} issues",
        f"Produced {len(enrichments)} enrichments",
        start,
        "context_enricher",
    )

    return {
        "enrichments": enrichments,
        "stage": STAStage.ENRICH_CONTEXT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enrich_context",
    }


# ------------------------------------------------------------------
# Node: create_ticket
# ------------------------------------------------------------------


async def create_ticket(
    state: SecurityTicketAutomatorState,
) -> dict[str, Any]:
    """Create security tickets on the target ticketing
    platform."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    tickets: list[dict[str, Any]] = []
    for i, issue in enumerate(state.issues):
        enrichment = state.enrichments[i] if i < len(state.enrichments) else {}
        result = await toolkit.create_ticket(
            issue=issue,
            platform=state.platform.value,
            enrichment=enrichment,
        )
        tickets.append(result)

    step = _step(
        state.reasoning_chain,
        "create_ticket",
        f"Creating tickets for {len(state.issues)} issues",
        f"Created {len(tickets)} tickets",
        start,
        "ticket_creator",
    )

    return {
        "tickets": tickets,
        "tickets_created": len(tickets),
        "stage": STAStage.CREATE_TICKET,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "create_ticket",
    }


# ------------------------------------------------------------------
# Node: assign_owner
# ------------------------------------------------------------------


async def assign_owner(
    state: SecurityTicketAutomatorState,
) -> dict[str, Any]:
    """Assign created tickets to appropriate owners
    based on expertise and on-call rotation."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assignments: list[dict[str, Any]] = []
    for ticket in state.tickets:
        result = await toolkit.assign_owner(
            ticket=ticket,
            escalation_rules=state.escalation_rules,
        )

        # LLM enhancement per assignment
        try:
            ctx = _json.dumps(
                {
                    "ticket": ticket,
                    "escalation_rules": state.escalation_rules,
                },
                default=str,
            )
            llm_out = await llm_structured(
                system_prompt=SYSTEM_ASSIGN,
                user_prompt=f"Assign ticket owner:\n{ctx}",
                schema=OwnerAssignmentOutput,
            )
            result = {
                "assignee": llm_out.assignee,  # type: ignore[union-attr]
                "team": llm_out.team,  # type: ignore[union-attr]
                "rationale": llm_out.rationale,  # type: ignore[union-attr]
                "escalation_needed": llm_out.escalation_needed,  # type: ignore[union-attr]
            }
            logger.info(
                "llm_enhanced",
                node="assign_owner",
                assignee=llm_out.assignee,  # type: ignore[union-attr]
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="assign_owner",
            )

        assignments.append(result)

    step = _step(
        state.reasoning_chain,
        "assign_owner",
        f"Assigning {len(state.tickets)} tickets",
        f"Assigned {len(assignments)} tickets",
        start,
        "owner_assigner",
    )

    return {
        "assignments": assignments,
        "stage": STAStage.ASSIGN_OWNER,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assign_owner",
    }


# ------------------------------------------------------------------
# Node: track_sla
# ------------------------------------------------------------------


async def track_sla(
    state: SecurityTicketAutomatorState,
) -> dict[str, Any]:
    """Track SLA compliance for all created tickets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sla_statuses = await toolkit.track_sla(
        tickets=state.tickets,
    )

    compliant = sum(1 for s in sla_statuses if not s.get("breached", False))
    breached = len(sla_statuses) - compliant

    step = _step(
        state.reasoning_chain,
        "track_sla",
        f"Tracking SLA for {len(state.tickets)} tickets",
        f"{compliant} compliant, {breached} breached",
        start,
        "sla_tracker",
    )

    return {
        "sla_statuses": sla_statuses,
        "sla_compliant_count": compliant,
        "sla_breach_count": breached,
        "stage": STAStage.TRACK_SLA,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "track_sla",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecurityTicketAutomatorState,
) -> dict[str, Any]:
    """Generate the final ticket automation report with
    SLA compliance and recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    total = state.tickets_created if state.tickets_created > 0 else 1
    compliance_rate = (state.sla_compliant_count / total) * 100

    report: dict[str, Any] = {
        "total_issues": state.total_issues,
        "tickets_created": state.tickets_created,
        "sla_compliant": state.sla_compliant_count,
        "sla_breached": state.sla_breach_count,
        "compliance_rate": compliance_rate,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "total_issues": state.total_issues,
                "tickets_created": state.tickets_created,
                "sla_compliant": state.sla_compliant_count,
                "sla_breached": state.sla_breach_count,
                "tickets_sample": state.tickets[:5],
                "assignments_sample": state.assignments[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate ticket report:\n{ctx}",
            schema=TicketReportOutput,
        )
        if isinstance(llm_out, TicketReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "risk_overview": llm_out.risk_overview,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recommendations=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record metrics
    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    await toolkit.record_metric(
        run_id=state.request_id,
        outcome={
            "total_issues": state.total_issues,
            "tickets_created": state.tickets_created,
            "sla_compliant": state.sla_compliant_count,
            "compliance_rate": compliance_rate,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.tickets_created} tickets",
        f"Report generated, SLA compliance={compliance_rate:.1f}%",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": STAStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
