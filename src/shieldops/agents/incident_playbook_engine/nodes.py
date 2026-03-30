"""Node implementations for the Incident Playbook Engine."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.agents.incident_playbook_engine.models import (
    IncidentCategory,
    IncidentPlaybookEngineState,
    IPEStage,
    ReasoningStep,
)
from shieldops.agents.incident_playbook_engine.prompts import (
    SYSTEM_ADAPT_STEPS,
    SYSTEM_CLASSIFY,
    SYSTEM_REPORT,
    SYSTEM_SELECT_PLAYBOOK,
    SYSTEM_VALIDATE,
    AdaptStepsOutput,
    ClassifyIncidentOutput,
    ReportOutput,
    SelectPlaybookOutput,
    ValidateOutcomeOutput,
)
from shieldops.agents.incident_playbook_engine.tools import (
    IncidentPlaybookEngineToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: IncidentPlaybookEngineToolkit | None = None


def set_toolkit(
    toolkit: IncidentPlaybookEngineToolkit,
) -> None:
    """Set the shared toolkit instance for all nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> IncidentPlaybookEngineToolkit:
    if _toolkit is None:
        return IncidentPlaybookEngineToolkit()
    return _toolkit


async def classify_incident(
    state: IncidentPlaybookEngineState,
) -> dict[str, Any]:
    """Classify the incident from alert context."""
    start = time.time()
    toolkit = _get_toolkit()

    classification = await toolkit.classify_incident(
        title=state.alert_title,
        description=state.alert_description,
        severity=state.alert_severity,
        indicators=state.alert_indicators,
        affected_assets=state.affected_assets,
    )

    # LLM enhancement
    try:
        context = _json.dumps(
            {
                "title": state.alert_title,
                "description": state.alert_description,
                "source": state.alert_source,
                "severity": state.alert_severity,
                "indicators": state.alert_indicators,
                "affected_assets": state.affected_assets,
                "heuristic_category": classification.category.value,
                "heuristic_severity": classification.severity,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CLASSIFY,
            user_prompt=(f"Classify this incident:\n{context}"),
            schema=ClassifyIncidentOutput,
        )
        if hasattr(llm_result, "category"):
            llm_cat = getattr(llm_result, "category", "")
            cats = [c.value for c in IncidentCategory]
            if llm_cat in cats:
                classification.category = IncidentCategory(llm_cat)
            llm_reason = getattr(llm_result, "reasoning", "")
            if llm_reason:
                classification.reasoning = f"{classification.reasoning} | LLM: {llm_reason}"
            llm_conf = getattr(llm_result, "confidence", None)
            if llm_conf is not None:
                classification.confidence = float(llm_conf)
        logger.info("llm_enhanced", node="classify_incident")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify_incident",
        )

    step = ReasoningStep(
        step="classify_incident",
        detail=(
            f"Classified as {classification.category.value} "
            f"({classification.severity}) with confidence "
            f"{classification.confidence:.2f}"
        ),
        confidence=("high" if classification.confidence >= 0.7 else "medium"),
        metadata={
            "category": classification.category.value,
            "severity": classification.severity,
            "confidence": classification.confidence,
        },
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "classification": classification,
        "stage": IPEStage.SELECT_PLAYBOOK,
        "current_step": "classify_incident",
        "reasoning_chain": [*state.reasoning_chain, step],
        "session_start": (start if state.session_start == 0.0 else state.session_start),
        "stats": {
            **state.stats,
            "classify_ms": elapsed,
        },
    }


async def select_playbook(
    state: IncidentPlaybookEngineState,
) -> dict[str, Any]:
    """Select the best playbook for the classified incident."""
    start = time.time()
    toolkit = _get_toolkit()

    candidates = await toolkit.select_playbooks(
        state.classification,
    )
    selected = candidates[0] if candidates else state.selected_playbook

    # LLM enhancement
    try:
        context = _json.dumps(
            {
                "classification": state.classification.model_dump(),
                "candidates": [c.model_dump() for c in candidates[:3]],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SELECT_PLAYBOOK,
            user_prompt=(f"Select the best playbook:\n{context}"),
            schema=SelectPlaybookOutput,
        )
        if hasattr(llm_result, "playbook_name"):
            llm_name = getattr(llm_result, "playbook_name", "")
            for c in candidates:
                if llm_name.lower() in c.name.lower():
                    selected = c
                    break
        logger.info("llm_enhanced", node="select_playbook")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="select_playbook",
        )

    step = ReasoningStep(
        step="select_playbook",
        detail=(
            f"Selected '{selected.name}' "
            f"(match={selected.match_score:.2f}, "
            f"success_rate={selected.historical_success_rate:.0%})"
        ),
        confidence="high",
        metadata={
            "playbook_id": selected.id,
            "match_score": selected.match_score,
            "candidates": len(candidates),
        },
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "candidate_playbooks": candidates,
        "selected_playbook": selected,
        "stage": IPEStage.ADAPT_STEPS,
        "current_step": "select_playbook",
        "reasoning_chain": [*state.reasoning_chain, step],
        "stats": {
            **state.stats,
            "select_ms": elapsed,
            "candidates_evaluated": len(candidates),
        },
    }


async def adapt_steps(
    state: IncidentPlaybookEngineState,
) -> dict[str, Any]:
    """Adapt playbook steps to the specific incident context."""
    start = time.time()
    toolkit = _get_toolkit()

    steps = await toolkit.build_execution_plan(
        state.selected_playbook,
        state.classification,
    )

    # LLM enhancement: adapt steps
    try:
        context = _json.dumps(
            {
                "playbook": state.selected_playbook.model_dump(),
                "classification": state.classification.model_dump(),
                "steps": [s.model_dump() for s in steps],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ADAPT_STEPS,
            user_prompt=(f"Adapt these playbook steps:\n{context}"),
            schema=AdaptStepsOutput,
        )
        if hasattr(llm_result, "adapted_steps"):
            adapted = getattr(llm_result, "adapted_steps", [])
            for i, desc in enumerate(adapted):
                if i < len(steps):
                    steps[i].description = desc
        logger.info("llm_enhanced", node="adapt_steps")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="adapt_steps",
        )

    from shieldops.agents.incident_playbook_engine.models import (
        PlaybookExecution,
        PlaybookStatus,
    )

    execution = PlaybookExecution(
        id=f"exec-{state.request_id}",
        playbook_id=state.selected_playbook.id,
        status=PlaybookStatus.ACTIVE,
        steps=steps,
    )

    step = ReasoningStep(
        step="adapt_steps",
        detail=(f"Adapted {len(steps)} steps for {state.classification.category.value} incident"),
        confidence="high",
        metadata={
            "step_count": len(steps),
            "approval_required": sum(1 for s in steps if s.requires_approval),
        },
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "execution": execution,
        "stage": IPEStage.EXECUTE_PLAYBOOK,
        "current_step": "adapt_steps",
        "reasoning_chain": [*state.reasoning_chain, step],
        "stats": {
            **state.stats,
            "adapt_ms": elapsed,
            "step_count": len(steps),
        },
    }


async def execute_playbook(
    state: IncidentPlaybookEngineState,
) -> dict[str, Any]:
    """Execute the adapted playbook steps."""
    start = time.time()
    toolkit = _get_toolkit()

    execution = await toolkit.execute_playbook(
        state.selected_playbook,
        state.execution.steps,
    )

    step = ReasoningStep(
        step="execute_playbook",
        detail=(
            f"Executed playbook: {execution.steps_completed}/"
            f"{len(execution.steps)} steps completed, "
            f"status={execution.status.value}"
        ),
        confidence=("high" if execution.status.value == "completed" else "low"),
        metadata={
            "status": execution.status.value,
            "completed": execution.steps_completed,
            "failed": execution.steps_failed,
            "rollback": execution.rollback_triggered,
            "duration_ms": execution.total_duration_ms,
        },
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "execution": execution,
        "stage": IPEStage.VALIDATE_OUTCOME,
        "current_step": "execute_playbook",
        "reasoning_chain": [*state.reasoning_chain, step],
        "stats": {
            **state.stats,
            "execute_ms": elapsed,
            "steps_completed": execution.steps_completed,
            "steps_failed": execution.steps_failed,
        },
    }


async def validate_outcome(
    state: IncidentPlaybookEngineState,
) -> dict[str, Any]:
    """Validate the playbook execution outcome."""
    start = time.time()
    toolkit = _get_toolkit()

    outcome = await toolkit.validate_outcome(
        state.execution,
        state.classification,
    )

    # LLM enhancement
    try:
        context = _json.dumps(
            {
                "execution": state.execution.model_dump(),
                "classification": state.classification.model_dump(),
                "outcome": outcome.model_dump(),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VALIDATE,
            user_prompt=(f"Validate this outcome:\n{context}"),
            schema=ValidateOutcomeOutput,
        )
        if hasattr(llm_result, "residual_risk"):
            llm_risk = getattr(llm_result, "residual_risk", "")
            if llm_risk:
                outcome.residual_risk = llm_risk
            llm_recs = getattr(llm_result, "recommendations", [])
            if llm_recs:
                outcome.recommendations = llm_recs
            llm_lessons = getattr(llm_result, "lessons_learned", [])
            if llm_lessons:
                outcome.lessons_learned = llm_lessons
        logger.info("llm_enhanced", node="validate_outcome")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="validate_outcome",
        )

    step = ReasoningStep(
        step="validate_outcome",
        detail=(
            f"Outcome: success={outcome.success}, "
            f"residual_risk={outcome.residual_risk}, "
            f"threat_neutralized={outcome.threat_neutralized}"
        ),
        confidence=("high" if outcome.success else "medium"),
        metadata={
            "success": outcome.success,
            "residual_risk": outcome.residual_risk,
            "failed_checks": len(outcome.failed_checks),
        },
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "outcome": outcome,
        "stage": IPEStage.REPORT,
        "current_step": "validate_outcome",
        "reasoning_chain": [*state.reasoning_chain, step],
        "stats": {
            **state.stats,
            "validate_ms": elapsed,
            "success": outcome.success,
            "residual_risk": outcome.residual_risk,
        },
    }


async def generate_report(
    state: IncidentPlaybookEngineState,
) -> dict[str, Any]:
    """Generate the final execution summary report."""
    start = time.time()
    total_elapsed = int((time.time() - state.session_start) * 1000)

    report_stats: dict[str, Any] = {
        "incident_category": state.classification.category.value,
        "incident_severity": state.classification.severity,
        "playbook_used": state.selected_playbook.name,
        "playbook_id": state.selected_playbook.id,
        "steps_total": len(state.execution.steps),
        "steps_completed": state.execution.steps_completed,
        "steps_failed": state.execution.steps_failed,
        "execution_status": state.execution.status.value,
        "outcome_success": state.outcome.success,
        "residual_risk": state.outcome.residual_risk,
        "threat_neutralized": state.outcome.threat_neutralized,
        "recommendations": state.outcome.recommendations,
        "lessons_learned": state.outcome.lessons_learned,
    }

    # LLM enhancement: executive summary
    try:
        context = _json.dumps(
            {
                "stats": report_stats,
                "classification": state.classification.model_dump(),
                "execution": state.execution.model_dump(),
                "outcome": state.outcome.model_dump(),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate execution report:\n{context}"),
            schema=ReportOutput,
        )
        if hasattr(llm_result, "executive_summary"):
            report_stats["executive_summary"] = getattr(llm_result, "executive_summary", "")
            report_stats["key_actions_taken"] = getattr(llm_result, "key_actions_taken", [])
            report_stats["risk_assessment"] = getattr(llm_result, "risk_assessment", "")
            report_stats["improvement_suggestions"] = getattr(
                llm_result, "improvement_suggestions", []
            )
        logger.info("llm_enhanced", node="generate_report")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    step = ReasoningStep(
        step="report",
        detail=(
            f"Generated report: "
            f"{'SUCCESS' if state.outcome.success else 'FAILED'} "
            f"— {state.selected_playbook.name}"
        ),
        confidence="high",
        metadata=report_stats,
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "stage": IPEStage.REPORT,
        "current_step": "report",
        "stats": {
            **state.stats,
            **report_stats,
            "report_ms": elapsed,
        },
        "reasoning_chain": [*state.reasoning_chain, step],
        "session_duration_ms": total_elapsed,
    }
