"""Node implementations for the IR Playbook Engine Agent."""

from __future__ import annotations

import json as _json
import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ir_playbook_engine.models import (
    IRPlaybookEngineState,
    IRStage,
    ResponseAdaptation,
)
from shieldops.agents.ir_playbook_engine.prompts import (
    SYSTEM_ADAPT,
    SYSTEM_CLASSIFY,
    SYSTEM_REPORT,
    SYSTEM_SELECT_PLAYBOOK,
    AdaptOutput,
    ClassifyOutput,
    PlaybookOutput,
    ReportOutput,
)
from shieldops.agents.ir_playbook_engine.tools import IRPlaybookEngineToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: IRPlaybookEngineToolkit | None = None


def set_toolkit(toolkit: IRPlaybookEngineToolkit) -> None:
    """Set the shared toolkit instance for all nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> IRPlaybookEngineToolkit:
    if _toolkit is None:
        return IRPlaybookEngineToolkit()
    return _toolkit


async def classify_incident(
    state: IRPlaybookEngineState,
) -> dict[str, Any]:
    """Classify the incoming incident by type and severity."""
    start = time.time()
    toolkit = _get_toolkit()

    classification = await toolkit.classify_incident(state.incident)

    # LLM enhancement
    try:
        context = _json.dumps(state.incident, default=str)
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CLASSIFY,
            user_prompt=f"Classify this incident:\n{context}",
            schema=ClassifyOutput,
        )
        if hasattr(llm_result, "incident_type"):
            llm_type = getattr(llm_result, "incident_type", "")
            if llm_type:
                from shieldops.agents.ir_playbook_engine.models import (
                    IncidentType,
                )

                valid = [t.value for t in IncidentType]
                if llm_type in valid:
                    classification.incident_type = IncidentType(llm_type)
            llm_sev = getattr(llm_result, "severity", "")
            if llm_sev:
                classification.severity = llm_sev
            llm_conf = getattr(llm_result, "confidence", None)
            if llm_conf is not None:
                classification.confidence = llm_conf
            llm_reason = getattr(llm_result, "reasoning", "")
            if llm_reason:
                classification.reasoning = f"{classification.reasoning} | LLM: {llm_reason}"
        logger.info("llm_enhanced", node="classify_incident")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="classify_incident")

    elapsed = int((time.time() - start) * 1000)

    logger.info(
        "ir_playbook.classify_done",
        request_id=state.request_id,
        incident_type=classification.incident_type.value,
        confidence=classification.confidence,
    )

    return {
        "classification": classification,
        "stage": IRStage.SELECT_PLAYBOOK,
        "current_step": "classify_incident",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Classified as {classification.incident_type.value} "
            f"(confidence={classification.confidence:.2f})",
        ],
        "session_start": (start if state.session_start == 0.0 else state.session_start),
        "stats": {**state.stats, "classify_ms": elapsed},
    }


async def select_playbook(
    state: IRPlaybookEngineState,
) -> dict[str, Any]:
    """Select the best playbook for the classified incident."""
    start = time.time()
    toolkit = _get_toolkit()

    playbook = await toolkit.select_playbook(state.classification)

    # LLM enhancement
    try:
        context = _json.dumps(
            {
                "incident_type": state.classification.incident_type.value,
                "severity": state.classification.severity,
                "confidence": state.classification.confidence,
                "indicators": state.classification.indicators,
                "playbook_name": playbook.playbook_name,
                "steps": playbook.steps,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SELECT_PLAYBOOK,
            user_prompt=(f"Validate playbook selection:\n{context}"),
            schema=PlaybookOutput,
        )
        if hasattr(llm_result, "selection_reason"):
            llm_reason = getattr(llm_result, "selection_reason", "")
            if llm_reason:
                playbook.selection_reason = f"{playbook.selection_reason} | LLM: {llm_reason}"
        logger.info("llm_enhanced", node="select_playbook")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="select_playbook")

    elapsed = int((time.time() - start) * 1000)

    logger.info(
        "ir_playbook.playbook_selected",
        request_id=state.request_id,
        playbook=playbook.playbook_name,
        steps=len(playbook.steps),
    )

    return {
        "playbook": playbook,
        "stage": IRStage.EXECUTE_STEPS,
        "current_step": "select_playbook",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Selected playbook '{playbook.playbook_name}' with {len(playbook.steps)} steps",
        ],
        "stats": {**state.stats, "select_ms": elapsed},
    }


async def execute_steps(
    state: IRPlaybookEngineState,
) -> dict[str, Any]:
    """Execute all steps in the selected playbook."""
    start = time.time()
    toolkit = _get_toolkit()

    step_results = []
    for i, step in enumerate(state.playbook.steps):
        result = await toolkit.execute_step(step, i)
        step_results.append(result)

    completed = sum(1 for s in step_results if s.status == "completed")
    failed = sum(1 for s in step_results if s.status == "failed")

    elapsed = int((time.time() - start) * 1000)

    logger.info(
        "ir_playbook.steps_executed",
        request_id=state.request_id,
        total=len(step_results),
        completed=completed,
        failed=failed,
    )

    return {
        "step_results": step_results,
        "stage": IRStage.ADAPT_RESPONSE,
        "current_step": "execute_steps",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Executed {len(step_results)} steps: {completed} completed, {failed} failed",
        ],
        "stats": {
            **state.stats,
            "execute_ms": elapsed,
            "steps_completed": completed,
            "steps_failed": failed,
        },
    }


async def adapt_response(
    state: IRPlaybookEngineState,
) -> dict[str, Any]:
    """Evaluate whether response adaptations are needed."""
    start = time.time()
    adaptations: list[ResponseAdaptation] = []

    failed_steps = [s for s in state.step_results if s.status == "failed"]

    # LLM-driven adaptation assessment
    for step in failed_steps:
        try:
            context = _json.dumps(
                {
                    "incident_type": (state.classification.incident_type.value),
                    "severity": state.classification.severity,
                    "failed_step": step.step_name,
                    "error": step.error,
                    "completed_steps": [
                        s.step_name for s in state.step_results if s.status == "completed"
                    ],
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_ADAPT,
                user_prompt=(f"Evaluate adaptation for:\n{context}"),
                schema=AdaptOutput,
            )
            should_adapt = getattr(llm_result, "should_adapt", False)
            if should_adapt:
                adaptations.append(
                    ResponseAdaptation(
                        id=f"adapt-{uuid4().hex[:12]}",
                        trigger=f"Step '{step.step_name}' failed",
                        original_step=step.step_name,
                        adapted_step=getattr(llm_result, "adapted_step", ""),
                        reason=getattr(llm_result, "reason", ""),
                        confidence=getattr(llm_result, "confidence", 0.0),
                    )
                )
            logger.info(
                "llm_enhanced",
                node="adapt_response",
                step=step.step_name,
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="adapt_response",
                step=step.step_name,
            )

    elapsed = int((time.time() - start) * 1000)

    logger.info(
        "ir_playbook.adaptations",
        request_id=state.request_id,
        adaptations=len(adaptations),
    )

    return {
        "adaptations": adaptations,
        "stage": IRStage.VALIDATE_CONTAINMENT,
        "current_step": "adapt_response",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Evaluated {len(failed_steps)} failed steps, produced {len(adaptations)} adaptations",
        ],
        "stats": {
            **state.stats,
            "adapt_ms": elapsed,
            "adaptations": len(adaptations),
        },
    }


async def validate_containment(
    state: IRPlaybookEngineState,
) -> dict[str, Any]:
    """Validate that containment measures are effective."""
    start = time.time()
    toolkit = _get_toolkit()

    checks = await toolkit.validate_containment(state.classification, state.step_results)
    all_passed = all(c.passed for c in checks)

    elapsed = int((time.time() - start) * 1000)

    logger.info(
        "ir_playbook.containment_validated",
        request_id=state.request_id,
        checks=len(checks),
        all_passed=all_passed,
    )

    return {
        "containment_checks": checks,
        "stage": IRStage.REPORT,
        "current_step": "validate_containment",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Containment validation: {len(checks)} checks, all passed={all_passed}",
        ],
        "stats": {
            **state.stats,
            "validate_ms": elapsed,
            "containment_passed": all_passed,
        },
    }


async def report(
    state: IRPlaybookEngineState,
) -> dict[str, Any]:
    """Generate final IR summary report."""
    start = time.time()
    total_elapsed = int((time.time() - state.session_start) * 1000)

    completed = sum(1 for s in state.step_results if s.status == "completed")
    failed = sum(1 for s in state.step_results if s.status == "failed")
    all_contained = all(c.passed for c in state.containment_checks)

    report_stats: dict[str, Any] = {
        "incident_type": state.classification.incident_type.value,
        "severity": state.classification.severity,
        "playbook": state.playbook.playbook_name,
        "steps_total": len(state.step_results),
        "steps_completed": completed,
        "steps_failed": failed,
        "adaptations": len(state.adaptations),
        "containment_passed": all_contained,
    }

    # LLM-generated executive summary
    try:
        context = _json.dumps(
            {
                **report_stats,
                "step_details": [s.model_dump() for s in state.step_results],
                "containment_checks": [c.model_dump() for c in state.containment_checks],
                "adaptations": [a.model_dump() for a in state.adaptations],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate IR report:\n{context}",
            schema=ReportOutput,
        )
        if hasattr(llm_result, "executive_summary"):
            report_stats["executive_summary"] = getattr(llm_result, "executive_summary", "")
            report_stats["key_actions"] = getattr(llm_result, "key_actions", [])
            report_stats["containment_status"] = getattr(llm_result, "containment_status", "")
            report_stats["recommendations"] = getattr(llm_result, "recommendations", [])
        logger.info("llm_enhanced", node="report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="report")

    elapsed = int((time.time() - start) * 1000)

    return {
        "stage": IRStage.REPORT,
        "current_step": "report",
        "stats": {**state.stats, **report_stats, "report_ms": elapsed},
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Generated IR report: {completed}/{len(state.step_results)} "
            f"steps completed, containment={'passed' if all_contained else 'failed'}",
        ],
        "session_duration_ms": total_elapsed,
    }
