"""Node implementations for the Security Orchestration
Hub Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_orchestration_hub.models import (
    ReasoningStep,
    SecurityOrchestrationHubState,
    SOHStage,
)
from shieldops.agents.security_orchestration_hub.prompts import (
    SYSTEM_CLASSIFY,
    SYSTEM_REPORT,
    SYSTEM_ROUTE,
    SYSTEM_VALIDATE,
    OrchestrationReportOutput,
    OutcomeValidationOutput,
    PlaybookRoutingOutput,
    SeverityClassificationOutput,
)
from shieldops.agents.security_orchestration_hub.tools import (
    SecurityOrchestrationHubToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityOrchestrationHubToolkit | None = None


def set_toolkit(
    toolkit: SecurityOrchestrationHubToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityOrchestrationHubToolkit:
    if _toolkit is None:
        return SecurityOrchestrationHubToolkit()
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
# Node: ingest_event
# ------------------------------------------------------------------


async def ingest_event(
    state: SecurityOrchestrationHubState,
) -> dict[str, Any]:
    """Ingest and normalize the incoming security event."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    events = await toolkit.ingest_event(
        raw_event=state.raw_event,
        source=state.event_source,
        event_type=state.event_type,
    )

    step = _step(
        state.reasoning_chain,
        "ingest_event",
        f"Source: {state.event_source}, type={state.event_type}",
        f"Ingested {len(events)} events",
        start,
        "event_ingester",
    )

    return {
        "events": events,
        "stage": SOHStage.INGEST_EVENT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "ingest_event",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: classify_severity
# ------------------------------------------------------------------


async def classify_severity(
    state: SecurityOrchestrationHubState,
) -> dict[str, Any]:
    """Classify the severity of ingested events."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications = await toolkit.classify_severity(
        events=state.events,
        context=state.raw_event,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "events": state.events[:5],
                "source": state.event_source,
                "event_type": state.event_type,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_CLASSIFY,
            user_prompt=f"Classify severity:\n{ctx}",
            schema=SeverityClassificationOutput,
        )
        if llm_out.indicators:  # type: ignore[union-attr]
            classifications.append(
                {
                    "classification_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "severity": llm_out.severity,  # type: ignore[union-attr]
                    "confidence": llm_out.confidence,  # type: ignore[union-attr]
                    "indicators": llm_out.indicators,  # type: ignore[union-attr]
                    "escalation_required": llm_out.escalation_required,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="classify_severity",
            severity=llm_out.severity,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify_severity",
        )

    step = _step(
        state.reasoning_chain,
        "classify_severity",
        f"Classifying {len(state.events)} events",
        f"Produced {len(classifications)} classifications",
        start,
        "severity_classifier",
    )

    return {
        "classifications": classifications,
        "stage": SOHStage.CLASSIFY_SEVERITY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "classify_severity",
    }


# ------------------------------------------------------------------
# Node: route_playbook
# ------------------------------------------------------------------


async def route_playbook(
    state: SecurityOrchestrationHubState,
) -> dict[str, Any]:
    """Route classified events to appropriate playbooks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    routes: list[dict[str, Any]] = []
    for classification in state.classifications:
        route = await toolkit.route_to_playbook(
            classification=classification,
        )

        # LLM enhancement
        try:
            ctx = _json.dumps(
                {"classification": classification},
                default=str,
            )
            llm_out = await llm_structured(
                system_prompt=SYSTEM_ROUTE,
                user_prompt=f"Route to playbook:\n{ctx}",
                schema=PlaybookRoutingOutput,
            )
            route = {
                "playbook_category": llm_out.playbook_category,  # type: ignore[union-attr]
                "steps": llm_out.steps,  # type: ignore[union-attr]
                "auto_approved": llm_out.auto_approved,  # type: ignore[union-attr]
                "rationale": llm_out.rationale,  # type: ignore[union-attr]
            }
            logger.info(
                "llm_enhanced",
                node="route_playbook",
                category=llm_out.playbook_category,  # type: ignore[union-attr]
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="route_playbook",
            )

        routes.append(route)

    step = _step(
        state.reasoning_chain,
        "route_playbook",
        (f"Routing {len(state.classifications)} classifications"),
        f"Routed to {len(routes)} playbooks",
        start,
        "playbook_engine",
    )

    return {
        "playbook_routes": routes,
        "stage": SOHStage.ROUTE_PLAYBOOK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "route_playbook",
    }


# ------------------------------------------------------------------
# Node: execute_actions
# ------------------------------------------------------------------


async def execute_actions(
    state: SecurityOrchestrationHubState,
) -> dict[str, Any]:
    """Execute orchestrated actions from routed playbooks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    all_results: list[dict[str, Any]] = []
    succeeded = 0

    for playbook in state.playbook_routes:
        results = await toolkit.execute_actions(
            playbook=playbook,
            events=state.events,
        )
        for r in results:
            all_results.append(r)
            if r.get("status") == "success":
                succeeded += 1

    step = _step(
        state.reasoning_chain,
        "execute_actions",
        (f"Executing {len(state.playbook_routes)} playbooks"),
        (f"{succeeded}/{len(all_results)} actions succeeded"),
        start,
        "action_executor",
    )

    return {
        "action_results": all_results,
        "actions_executed": len(all_results),
        "actions_succeeded": succeeded,
        "stage": SOHStage.EXECUTE_ACTIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_actions",
    }


# ------------------------------------------------------------------
# Node: validate_outcome
# ------------------------------------------------------------------


async def validate_outcome(
    state: SecurityOrchestrationHubState,
) -> dict[str, Any]:
    """Validate orchestration outcome against success
    criteria."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    validation = await toolkit.validate_outcome(
        action_results=state.action_results,
        expected_outcome={
            "actions_executed": state.actions_executed,
        },
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "action_results": state.action_results[:10],
                "actions_executed": state.actions_executed,
                "actions_succeeded": state.actions_succeeded,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_VALIDATE,
            user_prompt=f"Validate outcome:\n{ctx}",
            schema=OutcomeValidationOutput,
        )
        if isinstance(llm_out, OutcomeValidationOutput):
            validation = {
                "validated": llm_out.validated,
                "success_rate": llm_out.success_rate,
                "rollback_needed": llm_out.rollback_needed,
                "summary": llm_out.summary,
            }
        logger.info(
            "llm_enhanced",
            node="validate_outcome",
            validated=llm_out.validated,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="validate_outcome",
        )

    step = _step(
        state.reasoning_chain,
        "validate_outcome",
        (f"Validating {state.actions_executed} actions"),
        f"Validated: {validation.get('validated', False)}",
        start,
        "outcome_validator",
    )

    return {
        "validations": [*state.validations, validation],
        "outcome_validated": validation.get("validated", False),
        "stage": SOHStage.VALIDATE_OUTCOME,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_outcome",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecurityOrchestrationHubState,
) -> dict[str, Any]:
    """Generate the final orchestration report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    report: dict[str, Any] = {
        "actions_executed": state.actions_executed,
        "actions_succeeded": state.actions_succeeded,
        "outcome_validated": state.outcome_validated,
        "duration_ms": duration_ms,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "event_source": state.event_source,
                "event_type": state.event_type,
                "severity": state.severity.value,
                "classifications": state.classifications[:5],
                "action_results": state.action_results[:10],
                "validations": state.validations[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate report:\n{ctx}",
            schema=OrchestrationReportOutput,
        )
        if isinstance(llm_out, OrchestrationReportOutput):
            report.update(
                {
                    "executive_summary": (llm_out.executive_summary),
                    "actions_taken": llm_out.actions_taken,
                    "recommendations": (llm_out.recommendations),
                    "effectiveness_rating": (llm_out.effectiveness_rating),
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

    await toolkit.record_metric(
        metric_name="orchestration_duration_ms",
        value=float(duration_ms),
        tags={"source": state.event_source},
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.actions_executed} actions"),
        "Report generated",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": SOHStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
