"""Node implementations for the Security Alert Router
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_alert_router.models import (
    ReasoningStep,
    SARStage,
    SecurityAlertRouterState,
)
from shieldops.agents.security_alert_router.prompts import (
    SYSTEM_CLASSIFY,
    SYSTEM_OWNER,
    SYSTEM_REPORT,
    ClassificationOutput,
    OwnerDeterminationOutput,
    RouterReportOutput,
)
from shieldops.agents.security_alert_router.tools import (
    SecurityAlertRouterToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityAlertRouterToolkit | None = None


def set_toolkit(
    toolkit: SecurityAlertRouterToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityAlertRouterToolkit:
    if _toolkit is None:
        return SecurityAlertRouterToolkit()
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
# Node: receive_alerts
# ------------------------------------------------------------------


async def receive_alerts(
    state: SecurityAlertRouterState,
) -> dict[str, Any]:
    """Receive security alerts from configured sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.receive_alerts(
        sources=state.alert_sources,
        scope=state.scope,
    )

    alerts: list[dict[str, Any]] = list(results)

    step = _step(
        state.reasoning_chain,
        "receive_alerts",
        f"Sources: {len(state.alert_sources)}",
        f"Received {len(alerts)} alerts",
        start,
        "alert_source",
    )

    return {
        "alerts": alerts,
        "total_alerts": len(alerts),
        "stage": SARStage.RECEIVE_ALERTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "receive_alerts",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: classify_alerts
# ------------------------------------------------------------------


async def classify_alerts(
    state: SecurityAlertRouterState,
) -> dict[str, Any]:
    """Classify alerts by category and priority."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications = await toolkit.classify_alerts(
        alerts=state.alerts,
    )

    class_list: list[dict[str, Any]] = list(classifications)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "alert_count": len(state.alerts),
                "sample": state.alerts[:3],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_CLASSIFY,
            user_prompt=f"Classify security alerts:\n{ctx}",
            schema=ClassificationOutput,
        )
        _rand = random.randint(1000, 9999)  # noqa: S311
        class_list.append(
            {
                "classification_id": f"llm-{_rand}",
                "category": llm_out.category,  # type: ignore[union-attr]
                "priority": llm_out.priority,  # type: ignore[union-attr]
                "confidence": llm_out.confidence,  # type: ignore[union-attr]
                "tags": llm_out.tags,  # type: ignore[union-attr]
            }
        )
        logger.info(
            "llm_enhanced",
            node="classify_alerts",
            category=llm_out.category,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify_alerts",
        )

    step = _step(
        state.reasoning_chain,
        "classify_alerts",
        f"Classifying {len(state.alerts)} alerts",
        f"Classified {len(class_list)} alerts",
        start,
        "classifier",
    )

    return {
        "classifications": class_list,
        "stage": SARStage.CLASSIFY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "classify_alerts",
    }


# ------------------------------------------------------------------
# Node: determine_owner
# ------------------------------------------------------------------


async def determine_owner(
    state: SecurityAlertRouterState,
) -> dict[str, Any]:
    """Determine alert ownership based on classification."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assignments = await toolkit.determine_owner(
        classifications=state.classifications,
        rules=state.routing_rules,
    )

    assign_list: list[dict[str, Any]] = list(assignments)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "classifications_sample": state.classifications[:3],
                "rules": state.routing_rules,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_OWNER,
            user_prompt=f"Determine alert owners:\n{ctx}",
            schema=OwnerDeterminationOutput,
        )
        if llm_out.team:  # type: ignore[union-attr]
            assign_list.append(
                {
                    "team": llm_out.team,  # type: ignore[union-attr]
                    "reasoning": llm_out.reasoning,  # type: ignore[union-attr]
                    "sla_minutes": llm_out.sla_minutes,  # type: ignore[union-attr]
                    "escalation": llm_out.escalation_path,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="determine_owner",
            team=llm_out.team,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="determine_owner",
        )

    step = _step(
        state.reasoning_chain,
        "determine_owner",
        f"Determining owners for {len(state.classifications)} alerts",
        f"Assigned {len(assign_list)} owners",
        start,
        "team_registry",
    )

    return {
        "owner_assignments": assign_list,
        "stage": SARStage.DETERMINE_OWNER,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "determine_owner",
    }


# ------------------------------------------------------------------
# Node: route_to_team
# ------------------------------------------------------------------


async def route_to_team(
    state: SecurityAlertRouterState,
) -> dict[str, Any]:
    """Route alerts to assigned teams."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    routing = await toolkit.route_to_team(
        assignments=state.owner_assignments,
    )

    step = _step(
        state.reasoning_chain,
        "route_to_team",
        f"Routing {len(state.owner_assignments)} assignments",
        f"Routed {len(routing)} alerts",
        start,
        "notification_engine",
    )

    return {
        "routing_records": routing,
        "routed_count": len(routing),
        "stage": SARStage.ROUTE_ALERT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "route_to_team",
    }


# ------------------------------------------------------------------
# Node: track_acknowledgment
# ------------------------------------------------------------------


async def track_acknowledgment(
    state: SecurityAlertRouterState,
) -> dict[str, Any]:
    """Track alert acknowledgment and response times."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    acks = await toolkit.track_acknowledgment(
        routing_records=state.routing_records,
    )

    ack_list: list[dict[str, Any]] = list(acks)
    acked = sum(1 for a in ack_list if a.get("acknowledged"))
    response_times = [a.get("response_minutes", 0) for a in ack_list if a.get("acknowledged")]
    avg_response = sum(response_times) / len(response_times) if response_times else 0.0

    step = _step(
        state.reasoning_chain,
        "track_acknowledgment",
        f"Tracking {len(state.routing_records)} routed alerts",
        f"{acked} acknowledged, avg {avg_response:.1f}m",
        start,
        "ack_tracker",
    )

    return {
        "acknowledgments": ack_list,
        "acked_count": acked,
        "avg_response_minutes": avg_response,
        "stage": SARStage.TRACK_ACK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "track_acknowledgment",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecurityAlertRouterState,
) -> dict[str, Any]:
    """Generate the alert routing report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "total_alerts": state.total_alerts,
        "routed_count": state.routed_count,
        "acked_count": state.acked_count,
        "avg_response_minutes": state.avg_response_minutes,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "total_alerts": state.total_alerts,
                "routed": state.routed_count,
                "acked": state.acked_count,
                "avg_response": state.avg_response_minutes,
                "classifications_sample": state.classifications[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate routing report:\n{ctx}",
            schema=RouterReportOutput,
        )
        if isinstance(llm_out, RouterReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "sla_compliance": llm_out.sla_compliance,
                    "recommendations": llm_out.recommendations,
                    "bottlenecks": llm_out.bottlenecks,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                sla=llm_out.sla_compliance,
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    await toolkit.record_metric(
        request_id=state.request_id,
        outcome={
            "total": state.total_alerts,
            "routed": state.routed_count,
            "acked": state.acked_count,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_alerts} alerts",
        f"Report generated, {state.acked_count} acked",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": SARStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
