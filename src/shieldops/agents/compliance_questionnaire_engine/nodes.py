"""Node implementations for the Compliance Questionnaire
Engine Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.compliance_questionnaire_engine.models import (
    ComplianceQuestionnaireEngineState,
    CQEStage,
    ReasoningStep,
)
from shieldops.agents.compliance_questionnaire_engine.prompts import (
    SYSTEM_ANSWERS,
    SYSTEM_GAPS,
    SYSTEM_MAPPING,
    SYSTEM_REPORT,
    AnswerGenerationOutput,
    ControlMappingOutput,
    GapReviewOutput,
    QuestionnaireReportOutput,
)
from shieldops.agents.compliance_questionnaire_engine.tools import (
    ComplianceQuestionnaireEngineToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ComplianceQuestionnaireEngineToolkit | None = None


def _get_toolkit() -> ComplianceQuestionnaireEngineToolkit:
    if _toolkit is None:
        return ComplianceQuestionnaireEngineToolkit()
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
    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: receive_questionnaire
# ------------------------------------------------------------------


async def receive_questionnaire(
    state: ComplianceQuestionnaireEngineState,
) -> dict[str, Any]:
    """Parse and normalize the incoming questionnaire."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    parsed = await toolkit.receive_questionnaire(
        questions=state.questions,
        framework=state.framework.value,
        vendor_name=state.vendor_name,
    )

    step = _step(
        state.reasoning_chain,
        "receive_questionnaire",
        (f"Framework={state.framework}, vendor={state.vendor_name}"),
        f"Parsed {len(state.questions)} questions",
        start,
        "questionnaire_parser",
    )

    return {
        "parsed_questionnaire": parsed,
        "total_questions": len(state.questions),
        "stage": CQEStage.RECEIVE_QUESTIONNAIRE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "receive_questionnaire",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: map_controls
# ------------------------------------------------------------------


async def map_controls(
    state: ComplianceQuestionnaireEngineState,
) -> dict[str, Any]:
    """Map questionnaire questions to internal controls."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    mappings = await toolkit.map_to_controls(
        parsed_questionnaire=state.parsed_questionnaire,
        framework=state.framework.value,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "framework": state.framework.value,
                "questions": state.questions[:5],
                "vendor": state.vendor_name,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_MAPPING,
            user_prompt=f"Map controls for:\n{ctx}",
            schema=ControlMappingOutput,
        )
        if llm_out.mappings:  # type: ignore[union-attr]
            mappings = [
                *mappings,
                *llm_out.mappings,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="map_controls",
            count=len(llm_out.mappings),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="map_controls",
        )

    step = _step(
        state.reasoning_chain,
        "map_controls",
        f"Mapping {state.total_questions} questions",
        f"Mapped {len(mappings)} controls",
        start,
        "control_registry",
    )

    return {
        "control_mappings": mappings,
        "stage": CQEStage.MAP_CONTROLS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_controls",
    }


# ------------------------------------------------------------------
# Node: generate_answers
# ------------------------------------------------------------------


async def generate_answers(
    state: ComplianceQuestionnaireEngineState,
) -> dict[str, Any]:
    """Generate answers using mapped controls and evidence."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    answers = await toolkit.generate_answers(
        control_mappings=state.control_mappings,
        framework=state.framework.value,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "framework": state.framework.value,
                "mapping_count": len(state.control_mappings),
                "mappings_sample": state.control_mappings[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANSWERS,
            user_prompt=f"Generate answers for:\n{ctx}",
            schema=AnswerGenerationOutput,
        )
        if llm_out.answers:  # type: ignore[union-attr]
            rid = random.randint(1000, 9999)  # noqa: S311
            answers = [
                *answers,
                *[
                    {**a, "source": f"llm-{rid}"}
                    for a in llm_out.answers  # type: ignore[union-attr]
                ],
            ]
        logger.info(
            "llm_enhanced",
            node="generate_answers",
            count=len(llm_out.answers),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_answers",
        )

    answered = sum(1 for a in answers if a.get("status") != "gap")

    step = _step(
        state.reasoning_chain,
        "generate_answers",
        (f"Generating for {len(state.control_mappings)} mappings"),
        f"Generated {len(answers)} answers, {answered} complete",
        start,
        "answer_generator",
    )

    return {
        "generated_answers": answers,
        "answered_count": answered,
        "stage": CQEStage.GENERATE_ANSWERS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_answers",
    }


# ------------------------------------------------------------------
# Node: review_gaps
# ------------------------------------------------------------------


async def review_gaps(
    state: ComplianceQuestionnaireEngineState,
) -> dict[str, Any]:
    """Identify and assess gaps in questionnaire coverage."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    gaps = await toolkit.review_gaps(
        generated_answers=state.generated_answers,
        control_mappings=state.control_mappings,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "framework": state.framework.value,
                "answered": state.answered_count,
                "total": state.total_questions,
                "answers_sample": state.generated_answers[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_GAPS,
            user_prompt=f"Review gaps:\n{ctx}",
            schema=GapReviewOutput,
        )
        if llm_out.gaps:  # type: ignore[union-attr]
            gaps = [*gaps, *llm_out.gaps]  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="review_gaps",
            gap_count=len(llm_out.gaps),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="review_gaps",
        )

    step = _step(
        state.reasoning_chain,
        "review_gaps",
        (f"Reviewing {state.answered_count}/{state.total_questions} answers"),
        f"Found {len(gaps)} gaps",
        start,
        "gap_analyzer",
    )

    return {
        "gaps": gaps,
        "gap_count": len(gaps),
        "stage": CQEStage.REVIEW_GAPS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "review_gaps",
    }


# ------------------------------------------------------------------
# Node: finalize_response
# ------------------------------------------------------------------


async def finalize_response(
    state: ComplianceQuestionnaireEngineState,
) -> dict[str, Any]:
    """Finalize the questionnaire response package."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    finalized = await toolkit.finalize_response(
        generated_answers=state.generated_answers,
        gaps=state.gaps,
    )

    total = state.total_questions
    coverage = state.answered_count / total if total > 0 else 0.0

    step = _step(
        state.reasoning_chain,
        "finalize_response",
        (f"Finalizing {state.answered_count} answers, {state.gap_count} gaps"),
        f"Response finalized, coverage={coverage:.2f}",
        start,
        "response_compiler",
    )

    return {
        "finalized_response": finalized,
        "coverage_score": coverage,
        "stage": CQEStage.FINALIZE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "finalize_response",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: ComplianceQuestionnaireEngineState,
) -> dict[str, Any]:
    """Generate the final questionnaire report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric(
        metric_name="coverage_score",
        value=state.coverage_score,
        metadata={
            "framework": state.framework.value,
            "total_questions": state.total_questions,
        },
    )

    report: dict[str, Any] = {
        "questionnaire_name": state.questionnaire_name,
        "framework": state.framework.value,
        "total_questions": state.total_questions,
        "answered_count": state.answered_count,
        "gap_count": state.gap_count,
        "coverage_score": state.coverage_score,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "questionnaire_name": state.questionnaire_name,
                "framework": state.framework.value,
                "total_questions": state.total_questions,
                "answered_count": state.answered_count,
                "gap_count": state.gap_count,
                "coverage_score": state.coverage_score,
                "gaps_sample": state.gaps[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate questionnaire report:\n{ctx}"),
            schema=QuestionnaireReportOutput,
        )
        if isinstance(llm_out, QuestionnaireReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "gap_summary": llm_out.gap_summary,
                    "readiness_rating": llm_out.readiness_rating,
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

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_questions} questions"),
        (f"Report generated, coverage={state.coverage_score:.2f}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": CQEStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
