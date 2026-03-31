"""Node implementations for the Incident Cost Tracker
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.incident_cost_tracker.models import (
    ICTStage,
    IncidentCostTrackerState,
    ReasoningStep,
)
from shieldops.agents.incident_cost_tracker.prompts import (
    SYSTEM_DIRECT,
    SYSTEM_IDENTIFY,
    SYSTEM_INDIRECT,
    SYSTEM_REGULATORY,
    SYSTEM_REPORT,
    CostReportOutput,
    DirectCostOutput,
    IncidentIdentificationOutput,
    IndirectCostOutput,
    RegulatoryAssessmentOutput,
)
from shieldops.agents.incident_cost_tracker.tools import (
    IncidentCostTrackerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: IncidentCostTrackerToolkit | None = None


def set_toolkit(
    toolkit: IncidentCostTrackerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> IncidentCostTrackerToolkit:
    if _toolkit is None:
        return IncidentCostTrackerToolkit()
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
# Node: identify_incident
# ------------------------------------------------------------------


async def identify_incident(
    state: IncidentCostTrackerState,
) -> dict[str, Any]:
    """Identify and profile the security incident for
    cost analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    profile = await toolkit.identify_incident(
        incident_id=state.incident_id,
        incident_type=state.incident_type,
        severity=state.severity.value,
        scope=state.scope,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "incident_id": state.incident_id,
                "incident_type": state.incident_type,
                "severity": state.severity.value,
                "affected_systems": state.affected_systems,
                "records_exposed": state.records_exposed,
                "downtime_hours": state.downtime_hours,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_IDENTIFY,
            user_prompt=f"Identify incident:\n{ctx}",
            schema=IncidentIdentificationOutput,
        )
        profile.update(
            {
                "llm_type": llm_out.incident_type,  # type: ignore[union-attr]
                "llm_severity": llm_out.severity_assessment,  # type: ignore[union-attr]
                "blast_radius": llm_out.blast_radius,  # type: ignore[union-attr]
                "initial_estimate": llm_out.initial_cost_estimate_usd,  # type: ignore[union-attr]
            }
        )
        logger.info(
            "llm_enhanced",
            node="identify_incident",
            estimate=llm_out.initial_cost_estimate_usd,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="identify_incident",
        )

    step = _step(
        state.reasoning_chain,
        "identify_incident",
        f"Incident: {state.incident_id}, severity={state.severity}",
        "Incident profiled",
        start,
        "incident_manager",
    )

    return {
        "incident_profile": profile,
        "stage": ICTStage.IDENTIFY_INCIDENT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_incident",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: calculate_direct
# ------------------------------------------------------------------


async def calculate_direct(
    state: IncidentCostTrackerState,
) -> dict[str, Any]:
    """Calculate direct financial costs of incident
    response."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    costs = await toolkit.calculate_direct_costs(
        incident_profile=state.incident_profile,
        affected_systems=state.affected_systems,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "incident_profile": state.incident_profile,
                "affected_systems": state.affected_systems,
                "records_exposed": state.records_exposed,
                "downtime_hours": state.downtime_hours,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DIRECT,
            user_prompt=f"Calculate direct costs:\n{ctx}",
            schema=DirectCostOutput,
        )
        if llm_out.costs:  # type: ignore[union-attr]
            costs.append(
                {
                    "cost_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "costs": llm_out.costs,  # type: ignore[union-attr]
                    "total_usd": llm_out.total_usd,  # type: ignore[union-attr]
                    "major_drivers": llm_out.major_drivers,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="calculate_direct",
            total=llm_out.total_usd,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="calculate_direct",
        )

    total_direct = sum(c.get("amount_usd", 0.0) for c in costs)

    step = _step(
        state.reasoning_chain,
        "calculate_direct",
        f"Calculating costs for {len(state.affected_systems)} systems",
        f"Total direct: ${total_direct:,.0f}",
        start,
        "cost_calculator",
    )

    return {
        "direct_costs": costs,
        "total_direct_usd": total_direct,
        "stage": ICTStage.CALCULATE_DIRECT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "calculate_direct",
    }


# ------------------------------------------------------------------
# Node: estimate_indirect
# ------------------------------------------------------------------


async def estimate_indirect(
    state: IncidentCostTrackerState,
) -> dict[str, Any]:
    """Estimate indirect financial impact of the incident."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    costs = await toolkit.estimate_indirect_costs(
        incident_profile=state.incident_profile,
        direct_costs=state.direct_costs,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "incident_profile": state.incident_profile,
                "direct_costs_total": state.total_direct_usd,
                "records_exposed": state.records_exposed,
                "downtime_hours": state.downtime_hours,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_INDIRECT,
            user_prompt=f"Estimate indirect costs:\n{ctx}",
            schema=IndirectCostOutput,
        )
        if llm_out.costs:  # type: ignore[union-attr]
            costs.append(
                {
                    "cost_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "costs": llm_out.costs,  # type: ignore[union-attr]
                    "total_usd": llm_out.total_usd,  # type: ignore[union-attr]
                    "reputation_impact": llm_out.reputation_impact,  # type: ignore[union-attr]
                    "churn_estimate": llm_out.customer_churn_estimate,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="estimate_indirect",
            total=llm_out.total_usd,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="estimate_indirect",
        )

    total_indirect = sum(c.get("amount_usd", 0.0) for c in costs)

    step = _step(
        state.reasoning_chain,
        "estimate_indirect",
        f"Estimating indirect for {state.records_exposed} records",
        f"Total indirect: ${total_indirect:,.0f}",
        start,
        "impact_modeler",
    )

    return {
        "indirect_costs": costs,
        "total_indirect_usd": total_indirect,
        "stage": ICTStage.ESTIMATE_INDIRECT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "estimate_indirect",
    }


# ------------------------------------------------------------------
# Node: assess_regulatory
# ------------------------------------------------------------------


async def assess_regulatory(
    state: IncidentCostTrackerState,
) -> dict[str, Any]:
    """Assess regulatory fine exposure and notification
    obligations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    exposure = await toolkit.assess_regulatory_impact(
        incident_profile=state.incident_profile,
        records_exposed=state.records_exposed,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "incident_profile": state.incident_profile,
                "records_exposed": state.records_exposed,
                "affected_systems": state.affected_systems,
                "scope": state.scope,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REGULATORY,
            user_prompt=f"Assess regulatory exposure:\n{ctx}",
            schema=RegulatoryAssessmentOutput,
        )
        exposure.append(
            {
                "exposure_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                "regulations": llm_out.regulations_applicable,  # type: ignore[union-attr]
                "max_exposure_usd": llm_out.max_exposure_usd,  # type: ignore[union-attr]
                "estimated_fine_usd": llm_out.estimated_fine_usd,  # type: ignore[union-attr]
                "notification_required": llm_out.notification_required,  # type: ignore[union-attr]
                "recommendations": llm_out.recommendations,  # type: ignore[union-attr]
            }
        )
        logger.info(
            "llm_enhanced",
            node="assess_regulatory",
            exposure=llm_out.max_exposure_usd,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_regulatory",
        )

    total_regulatory = sum(e.get("estimated_fine_usd", 0.0) for e in exposure)

    step = _step(
        state.reasoning_chain,
        "assess_regulatory",
        f"Assessing regulatory for {state.records_exposed} records",
        f"Regulatory exposure: ${total_regulatory:,.0f}",
        start,
        "regulatory_engine",
    )

    return {
        "regulatory_exposure": exposure,
        "total_regulatory_usd": total_regulatory,
        "stage": ICTStage.ASSESS_REGULATORY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_regulatory",
    }


# ------------------------------------------------------------------
# Node: forecast_total
# ------------------------------------------------------------------


async def forecast_total(
    state: IncidentCostTrackerState,
) -> dict[str, Any]:
    """Forecast total incident cost with confidence
    intervals."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    forecast = await toolkit.forecast_total(
        direct_costs=state.direct_costs,
        indirect_costs=state.indirect_costs,
        regulatory_exposure=state.regulatory_exposure,
        insurance_coverage=state.insurance_coverage_usd,
    )

    grand_total = state.total_direct_usd + state.total_indirect_usd + state.total_regulatory_usd

    forecast.update(
        {
            "total_direct_usd": state.total_direct_usd,
            "total_indirect_usd": state.total_indirect_usd,
            "total_regulatory_usd": state.total_regulatory_usd,
            "grand_total_usd": grand_total,
        }
    )

    step = _step(
        state.reasoning_chain,
        "forecast_total",
        (f"Direct=${state.total_direct_usd:,.0f}, Indirect=${state.total_indirect_usd:,.0f}"),
        f"Grand total: ${grand_total:,.0f}",
        start,
        "cost_forecaster",
    )

    return {
        "forecast": forecast,
        "grand_total_usd": grand_total,
        "stage": ICTStage.FORECAST_TOTAL,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "forecast_total",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: IncidentCostTrackerState,
) -> dict[str, Any]:
    """Generate the final incident cost report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {}

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "incident_id": state.incident_id,
                "severity": state.severity.value,
                "total_direct_usd": state.total_direct_usd,
                "total_indirect_usd": state.total_indirect_usd,
                "total_regulatory_usd": state.total_regulatory_usd,
                "grand_total_usd": state.grand_total_usd,
                "records_exposed": state.records_exposed,
                "forecast": state.forecast,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate cost report:\n{ctx}",
            schema=CostReportOutput,
        )
        if isinstance(llm_out, CostReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "grand_total_usd": llm_out.grand_total_usd,
                    "recommendations": llm_out.recommendations,
                    "insurance_guidance": llm_out.insurance_guidance,
                    "risk_rating": llm_out.risk_rating,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                risk=llm_out.risk_rating,
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Track metric
    await toolkit.record_metric(
        metric_name="incident_cost_analysis_completed",
        value=state.grand_total_usd,
        tags={
            "incident_id": state.incident_id,
            "severity": state.severity.value,
        },
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on ${state.grand_total_usd:,.0f} total",
        "Cost report generated",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": ICTStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
