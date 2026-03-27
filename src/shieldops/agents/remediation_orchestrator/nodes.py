"""Node implementations for Remediation Orchestrator."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.remediation_orchestrator.models import (
    OrchestratorStage,
    ReasoningStep,
    RemediationOrchestratorState,
    RoutingDecision,
)
from shieldops.agents.remediation_orchestrator.prompts import (
    SYSTEM_CLASSIFY,
    SYSTEM_REPORT,
    ClassificationLLMResult,
    OrchestratorReportResult,
)
from shieldops.agents.remediation_orchestrator.tools import (
    RemediationOrchestratorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: RemediationOrchestratorToolkit | None = None


def set_toolkit(
    tk: RemediationOrchestratorToolkit,
) -> None:
    """Set module-level toolkit for all nodes."""
    global _toolkit
    _toolkit = tk


def _get_toolkit() -> RemediationOrchestratorToolkit:
    if _toolkit is None:
        return RemediationOrchestratorToolkit()
    return _toolkit


async def receive_findings(
    state: RemediationOrchestratorState,
) -> dict[str, Any]:
    """Receive findings from all sources."""
    start = datetime.now(UTC)
    tk = _get_toolkit()

    findings = await tk.receive_findings()

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="receive_findings",
        input_summary="all agent sources",
        output_summary=(f"Received {len(findings)} findings"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="intake_queue",
    )
    return {
        "findings_received": findings,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": (OrchestratorStage.RECEIVE_FINDINGS),
    }


async def classify_and_route(
    state: RemediationOrchestratorState,
) -> dict[str, Any]:
    """Classify and route each finding."""
    start = datetime.now(UTC)
    tk = _get_toolkit()
    classifications = []

    for finding in state.findings_received:
        classification = await tk.classify_finding(finding)

        # LLM-enhanced classification
        ctx = (
            f"Title: {finding.title}\n"
            f"Severity: {finding.severity}\n"
            f"CVSS: {finding.cvss_score}\n"
            f"Asset: {finding.affected_asset}\n"
            f"Auto-remediable: {finding.auto_remediable}\n"
            f"Source: {finding.source_agent}"
        )
        try:
            result = cast(
                ClassificationLLMResult,
                await llm_structured(
                    system_prompt=SYSTEM_CLASSIFY,
                    user_prompt=ctx,
                    schema=ClassificationLLMResult,
                ),
            )
            classification.rationale = result.rationale
        except Exception as e:
            logger.error("llm_classify_failed", error=str(e))

        classifications.append(classification)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="classify_and_route",
        input_summary=(f"{len(state.findings_received)} findings"),
        output_summary=(f"Classified {len(classifications)}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )
    return {
        "classified": classifications,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": (OrchestratorStage.CLASSIFY_AND_ROUTE),
    }


async def create_tickets(
    state: RemediationOrchestratorState,
) -> dict[str, Any]:
    """Create tickets for findings needing human work."""
    start = datetime.now(UTC)
    tk = _get_toolkit()
    tickets = []

    finding_map = {f.id: f for f in state.findings_received}

    ticket_routings = {
        RoutingDecision.CREATE_TICKET,
        RoutingDecision.ESCALATE,
    }

    for cls in state.classified:
        if cls.routing in ticket_routings:
            finding = finding_map.get(cls.finding_id)
            if finding:
                ticket = await tk.create_ticket(finding, cls)
                tickets.append(ticket)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="create_tickets",
        input_summary=(f"{len(state.classified)} classified"),
        output_summary=(f"Created {len(tickets)} tickets"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="jira_api",
    )
    return {
        "tickets_created": tickets,
        "tickets_opened": len(tickets),
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": (OrchestratorStage.CREATE_TICKETS),
    }


async def dispatch_remediation(
    state: RemediationOrchestratorState,
) -> dict[str, Any]:
    """Dispatch remediation agents for auto-fix."""
    start = datetime.now(UTC)
    tk = _get_toolkit()
    dispatches = []
    escalated = 0

    finding_map = {f.id: f for f in state.findings_received}

    for cls in state.classified:
        if cls.routing == RoutingDecision.AUTO_REMEDIATE:
            finding = finding_map.get(cls.finding_id)
            if finding:
                dispatch = await tk.dispatch_remediation(finding, cls)
                dispatches.append(dispatch)
        elif cls.routing == RoutingDecision.ESCALATE:
            escalated += 1

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="dispatch_remediation",
        input_summary=(f"{len(state.classified)} classified"),
        output_summary=(f"Dispatched {len(dispatches)}, escalated {escalated}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="agent_dispatcher",
    )
    return {
        "remediations_dispatched": dispatches,
        "auto_remediated_count": len(dispatches),
        "escalated": escalated,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": (OrchestratorStage.DISPATCH_REMEDIATION),
    }


async def track_progress(
    state: RemediationOrchestratorState,
) -> dict[str, Any]:
    """Track progress of dispatched remediations."""
    start = datetime.now(UTC)
    tk = _get_toolkit()
    tracking = []

    cls_map = {c.finding_id: c for c in state.classified}

    for dispatch in state.remediations_dispatched:
        cls = cls_map.get(dispatch.finding_id)
        if cls:
            progress = await tk.track_progress(dispatch, cls)
            tracking.append(progress)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="track_progress",
        input_summary=(f"{len(state.remediations_dispatched)} dispatched"),
        output_summary=(f"Tracked {len(tracking)} remediations"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="progress_tracker",
    )
    return {
        "progress_tracked": tracking,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": (OrchestratorStage.TRACK_PROGRESS),
    }


async def generate_report(
    state: RemediationOrchestratorState,
) -> dict[str, Any]:
    """Generate orchestration report."""
    start = datetime.now(UTC)

    ctx = (
        f"Findings: {len(state.findings_received)}\n"
        f"Auto-remediated: "
        f"{state.auto_remediated_count}\n"
        f"Tickets: {state.tickets_opened}\n"
        f"Escalated: {state.escalated}"
    )

    report = (
        f"Orchestration: "
        f"{state.auto_remediated_count} auto-fixed, "
        f"{state.tickets_opened} tickets, "
        f"{state.escalated} escalated."
    )

    try:
        result = cast(
            OrchestratorReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=ctx,
                schema=OrchestratorReportResult,
            ),
        )
        report = (
            f"{result.title}\n\n"
            f"{result.executive_summary}\n"
            f"Risk: {result.risk_assessment}\n"
            f"SLA: {result.sla_compliance}"
        )
    except Exception as e:
        logger.error("llm_report_failed", error=str(e))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=ctx[:100],
        output_summary=report[:200],
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    total = sum(s.duration_ms for s in [*state.reasoning_chain, step])
    return {
        "report_summary": report,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": OrchestratorStage.REPORT,
        "duration_ms": total,
    }
