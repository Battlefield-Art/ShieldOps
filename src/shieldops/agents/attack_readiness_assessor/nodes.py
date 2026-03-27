"""Attack Readiness Assessor Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    DetectionAssessment,
    PreventionAssessment,
    ReadinessStage,
    ResponseAssessment,
    ScenarioSelection,
)
from .prompts import (
    SYSTEM_ASSESS_DETECTION,
    SYSTEM_ASSESS_PREVENTION,
    SYSTEM_ASSESS_RESPONSE,
    SYSTEM_REPORT,
    DetectionAnalysisOutput,
    PreventionAnalysisOutput,
    ReadinessReportOutput,
    ResponseAnalysisOutput,
)
from .tools import AttackReadinessAssessorToolkit

logger = structlog.get_logger()


async def select_scenarios(
    state: dict[str, Any],
    toolkit: AttackReadinessAssessorToolkit,
) -> dict[str, Any]:
    """Select attack scenarios for assessment."""
    logger.info("readiness.node.select_scenarios")

    tenant_id = state.get("tenant_id", "")
    scenarios = state.get("scenarios")
    selected = await toolkit.select_scenarios(
        tenant_id,
        scenarios,
    )
    data = [s.model_dump() for s in selected]

    return {
        "current_stage": (ReadinessStage.SELECT_SCENARIOS.value),
        "scenarios_selected": data,
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Selected {len(selected)} attack scenarios"]
        ),
    }


async def assess_prevention(
    state: dict[str, Any],
    toolkit: AttackReadinessAssessorToolkit,
) -> dict[str, Any]:
    """Assess prevention capabilities."""
    logger.info("readiness.node.assess_prevention")

    raw = state.get("scenarios_selected", [])
    scenarios = [ScenarioSelection(**s) for s in raw]
    results = await toolkit.assess_prevention(
        scenarios,
    )

    # LLM enhancement
    for result in results:
        try:
            llm_result = await llm_structured(
                system_prompt=(SYSTEM_ASSESS_PREVENTION),
                user_prompt=(
                    f"Scenario: {result.scenario}\n"
                    f"Controls in place: "
                    f"{', '.join(result.controls_in_place)}\n"
                    f"Missing: "
                    f"{', '.join(result.controls_missing)}"
                ),
                output_schema=(PreventionAnalysisOutput),
            )
            result.effectiveness = llm_result.effectiveness
        except Exception:
            logger.debug(
                "readiness.llm_prevention_fallback",
                scenario=result.scenario,
            )

    data = [r.model_dump() for r in results]

    return {
        "current_stage": (ReadinessStage.ASSESS_PREVENTION.value),
        "prevention_scores": data,
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Assessed prevention for {len(results)} scenarios"]
        ),
    }


async def assess_detection(
    state: dict[str, Any],
    toolkit: AttackReadinessAssessorToolkit,
) -> dict[str, Any]:
    """Assess detection capabilities."""
    logger.info("readiness.node.assess_detection")

    raw = state.get("scenarios_selected", [])
    scenarios = [ScenarioSelection(**s) for s in raw]
    results = await toolkit.assess_detection(
        scenarios,
    )

    # LLM enhancement
    for result in results:
        try:
            llm_result = await llm_structured(
                system_prompt=(SYSTEM_ASSESS_DETECTION),
                user_prompt=(
                    f"Scenario: {result.scenario}\n"
                    f"Detection rules: "
                    f"{result.detection_rules}\n"
                    f"Coverage: "
                    f"{result.coverage_pct}%\n"
                    f"Gaps: {', '.join(result.gaps)}"
                ),
                output_schema=(DetectionAnalysisOutput),
            )
            if llm_result.gaps:
                result.gaps = llm_result.gaps
        except Exception:
            logger.debug(
                "readiness.llm_detection_fallback",
                scenario=result.scenario,
            )

    data = [r.model_dump() for r in results]

    return {
        "current_stage": (ReadinessStage.ASSESS_DETECTION.value),
        "detection_scores": data,
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Assessed detection for {len(results)} scenarios"]
        ),
    }


async def assess_response(
    state: dict[str, Any],
    toolkit: AttackReadinessAssessorToolkit,
) -> dict[str, Any]:
    """Assess response capabilities."""
    logger.info("readiness.node.assess_response")

    raw = state.get("scenarios_selected", [])
    scenarios = [ScenarioSelection(**s) for s in raw]
    results = await toolkit.assess_response(
        scenarios,
    )

    # LLM enhancement
    for result in results:
        try:
            llm_result = await llm_structured(
                system_prompt=(SYSTEM_ASSESS_RESPONSE),
                user_prompt=(
                    f"Scenario: {result.scenario}\n"
                    f"Runbook: {result.runbook_exists}\n"
                    f"Automation: "
                    f"{result.automation_level}\n"
                    f"MTTR: "
                    f"{result.mean_time_to_respond}"
                ),
                output_schema=(ResponseAnalysisOutput),
            )
            if llm_result.gaps:
                result.gaps = llm_result.gaps
        except Exception:
            logger.debug(
                "readiness.llm_response_fallback",
                scenario=result.scenario,
            )

    data = [r.model_dump() for r in results]

    return {
        "current_stage": (ReadinessStage.ASSESS_RESPONSE.value),
        "response_scores": data,
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Assessed response for {len(results)} scenarios"]
        ),
    }


async def calculate_readiness(
    state: dict[str, Any],
    toolkit: AttackReadinessAssessorToolkit,
) -> dict[str, Any]:
    """Calculate overall readiness scores."""
    logger.info("readiness.node.calculate_readiness")

    prev = [PreventionAssessment(**p) for p in state.get("prevention_scores", [])]
    det = [DetectionAssessment(**d) for d in state.get("detection_scores", [])]
    resp = [ResponseAssessment(**r) for r in state.get("response_scores", [])]

    scores = await toolkit.calculate_readiness(
        prev,
        det,
        resp,
    )
    data = [s.model_dump() for s in scores]

    # Determine overall and weakest
    if scores:
        avg = sum(s.overall_score for s in scores) / len(scores)
        weakest = scores[0]
        overall = "good" if avg >= 70 else "adequate" if avg >= 55 else "insufficient"
    else:
        avg = 0.0
        overall = "unknown"
        weakest = None

    return {
        "current_stage": (ReadinessStage.CALCULATE_READINESS.value),
        "readiness_scores": data,
        "overall_readiness": overall,
        "weakest_area": (weakest.scenario.value if weakest else ""),
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Overall readiness: {overall} (avg {avg:.1f})"]
        ),
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: AttackReadinessAssessorToolkit,
) -> dict[str, Any]:
    """Generate final readiness report."""
    logger.info("readiness.node.generate_report")

    try:
        context = json.dumps(
            {
                "overall_readiness": state.get(
                    "overall_readiness",
                    "",
                ),
                "weakest_area": state.get(
                    "weakest_area",
                    "",
                ),
                "readiness_scores": state.get(
                    "readiness_scores",
                    [],
                )[:5],
            },
            default=str,
        )
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Readiness assessment:\n{context}"),
            output_schema=ReadinessReportOutput,
        )
        summary = result.executive_summary
    except Exception:
        logger.debug(
            "readiness.llm_report_fallback",
        )
        overall = state.get(
            "overall_readiness",
            "unknown",
        )
        weakest = state.get("weakest_area", "N/A")
        summary = f"Readiness: {overall}. Weakest: {weakest}."

    return {
        "current_stage": (ReadinessStage.REPORT.value),
        "reasoning_chain": (state.get("reasoning_chain", []) + [f"Report: {summary[:120]}"]),
    }
