"""Node implementations for the Security Training Tracker
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_training_tracker.models import (
    ReasoningStep,
    SecurityTrainingTrackerState,
    STTStage,
)
from shieldops.agents.security_training_tracker.prompts import (
    SYSTEM_EFFECTIVENESS,
    SYSTEM_GAPS,
    SYSTEM_REPORT,
    SYSTEM_REQUIREMENTS,
    EffectivenessOutput,
    GapAnalysisOutput,
    RequirementAssessmentOutput,
    TrainingReportOutput,
)
from shieldops.agents.security_training_tracker.tools import (
    SecurityTrainingTrackerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityTrainingTrackerToolkit | None = None


def set_toolkit(
    toolkit: SecurityTrainingTrackerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityTrainingTrackerToolkit:
    if _toolkit is None:
        return SecurityTrainingTrackerToolkit()
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
# Node: assess_requirements
# ------------------------------------------------------------------


async def assess_requirements(
    state: SecurityTrainingTrackerState,
) -> dict[str, Any]:
    """Assess security training requirements for the
    organization."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.assess_requirements(
        org_units=state.org_units,
        frameworks=state.compliance_frameworks,
    )

    requirements: list[dict[str, Any]] = list(results)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "org_units": state.org_units,
                "frameworks": state.compliance_frameworks,
                "scope": state.scope,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REQUIREMENTS,
            user_prompt=f"Assess training requirements:\n{ctx}",
            schema=RequirementAssessmentOutput,
        )
        if llm_out.requirements:  # type: ignore[union-attr]
            requirements = [
                *requirements,
                *llm_out.requirements,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="assess_requirements",
            count=len(llm_out.requirements),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_requirements",
        )

    step = _step(
        state.reasoning_chain,
        "assess_requirements",
        f"Org units: {len(state.org_units)}, frameworks: {len(state.compliance_frameworks)}",
        f"Identified {len(requirements)} requirements",
        start,
        "compliance_engine",
    )

    return {
        "requirements": requirements,
        "total_requirements": len(requirements),
        "stage": STTStage.ASSESS_REQUIREMENTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_requirements",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: track_completion
# ------------------------------------------------------------------


async def track_completion(
    state: SecurityTrainingTrackerState,
) -> dict[str, Any]:
    """Track training completion across the organization."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    completions = await toolkit.track_completion(
        requirements=state.requirements,
    )

    completion_list: list[dict[str, Any]] = list(completions)
    overdue = sum(1 for c in completion_list if c.get("status") == "overdue")
    completed = sum(1 for c in completion_list if c.get("status") == "completed")
    total = len(completion_list) if completion_list else 1
    rate = (completed / total) * 100.0

    step = _step(
        state.reasoning_chain,
        "track_completion",
        f"Tracking {len(state.requirements)} requirements",
        f"{completed}/{total} complete, {overdue} overdue",
        start,
        "lms_client",
    )

    return {
        "completions": completion_list,
        "completion_rate": rate,
        "overdue_count": overdue,
        "stage": STTStage.TRACK_COMPLETION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "track_completion",
    }


# ------------------------------------------------------------------
# Node: measure_effectiveness
# ------------------------------------------------------------------


async def measure_effectiveness(
    state: SecurityTrainingTrackerState,
) -> dict[str, Any]:
    """Measure training program effectiveness."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    metrics = await toolkit.measure_effectiveness(
        completions=state.completions,
    )

    metrics_list: list[dict[str, Any]] = list(metrics)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "completion_rate": state.completion_rate,
                "completions_sample": state.completions[:5],
                "overdue": state.overdue_count,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_EFFECTIVENESS,
            user_prompt=f"Measure training effectiveness:\n{ctx}",
            schema=EffectivenessOutput,
        )
        _rand = random.randint(1000, 9999)  # noqa: S311
        metrics_list.append(
            {
                "metric_id": f"llm-{_rand}",
                "overall_score": llm_out.overall_score,  # type: ignore[union-attr]
                "strongest": llm_out.strongest_areas,  # type: ignore[union-attr]
                "weakest": llm_out.weakest_areas,  # type: ignore[union-attr]
                "behavior_impact": llm_out.behavior_impact,  # type: ignore[union-attr]
            }
        )
        logger.info(
            "llm_enhanced",
            node="measure_effectiveness",
            score=llm_out.overall_score,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="measure_effectiveness",
        )

    step = _step(
        state.reasoning_chain,
        "measure_effectiveness",
        f"Measuring {len(state.completions)} completions",
        f"Produced {len(metrics_list)} effectiveness metrics",
        start,
        "phishing_sim",
    )

    return {
        "effectiveness": metrics_list,
        "stage": STTStage.MEASURE_EFFECTIVENESS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "measure_effectiveness",
    }


# ------------------------------------------------------------------
# Node: identify_gaps
# ------------------------------------------------------------------


async def identify_gaps(
    state: SecurityTrainingTrackerState,
) -> dict[str, Any]:
    """Identify gaps in training coverage."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    gaps = await toolkit.identify_gaps(
        requirements=state.requirements,
        completions=state.completions,
        effectiveness=state.effectiveness,
    )

    gap_list: list[dict[str, Any]] = list(gaps)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "requirements_count": len(state.requirements),
                "completion_rate": state.completion_rate,
                "overdue": state.overdue_count,
                "effectiveness_sample": state.effectiveness[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_GAPS,
            user_prompt=f"Identify training gaps:\n{ctx}",
            schema=GapAnalysisOutput,
        )
        if llm_out.gaps:  # type: ignore[union-attr]
            for idx, gap in enumerate(llm_out.gaps):  # type: ignore[union-attr]
                gap_list.append(
                    {
                        "gap_id": f"llm-{idx}",
                        "category": gap.get("category", ""),
                        "risk_level": gap.get("risk_level", ""),
                        "compliance_risk": llm_out.compliance_risk,  # type: ignore[union-attr]
                    }
                )
        logger.info(
            "llm_enhanced",
            node="identify_gaps",
            gaps=len(llm_out.gaps),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="identify_gaps",
        )

    step = _step(
        state.reasoning_chain,
        "identify_gaps",
        f"Analyzing {len(state.requirements)} requirements",
        f"Found {len(gap_list)} training gaps",
        start,
        "gap_analyzer",
    )

    return {
        "gaps": gap_list,
        "gap_count": len(gap_list),
        "stage": STTStage.IDENTIFY_GAPS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_gaps",
    }


# ------------------------------------------------------------------
# Node: assign_remediation
# ------------------------------------------------------------------


async def assign_remediation(
    state: SecurityTrainingTrackerState,
) -> dict[str, Any]:
    """Assign remediation actions for training gaps."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    remediations = await toolkit.assign_remediation(
        gaps=state.gaps,
    )

    step = _step(
        state.reasoning_chain,
        "assign_remediation",
        f"Remediating {len(state.gaps)} gaps",
        f"Assigned {len(remediations)} remediation actions",
        start,
        "notification_engine",
    )

    return {
        "remediations": remediations,
        "stage": STTStage.REMEDIATE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assign_remediation",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecurityTrainingTrackerState,
) -> dict[str, Any]:
    """Generate the training tracker report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "total_requirements": state.total_requirements,
        "completion_rate": state.completion_rate,
        "overdue_count": state.overdue_count,
        "gap_count": state.gap_count,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "requirements": state.total_requirements,
                "completion_rate": state.completion_rate,
                "overdue": state.overdue_count,
                "gaps": state.gap_count,
                "effectiveness_sample": state.effectiveness[:5],
                "gaps_sample": state.gaps[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate training report:\n{ctx}",
            schema=TrainingReportOutput,
        )
        if isinstance(llm_out, TrainingReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "compliance_status": llm_out.compliance_status,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recs=len(llm_out.recommendations),
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
            "requirements": state.total_requirements,
            "completion_rate": state.completion_rate,
            "overdue": state.overdue_count,
            "gaps": state.gap_count,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_requirements} requirements",
        f"Report generated, {state.completion_rate:.1f}% complete",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": STTStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
