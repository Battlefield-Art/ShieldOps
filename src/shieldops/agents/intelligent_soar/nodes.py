"""Node implementations for the Intelligent SOAR Agent.

LangGraph-native playbook execution with dynamic
mid-execution adaptation — the core differentiator
vs Palo Alto Cortex XSOAR's rigid visual playbooks.
"""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.intelligent_soar.models import (
    AdaptiveDecision,
    ExecutionStep,
    IntelligentSOARState,
    OutcomeValidation,
    PlaybookSelection,
    SOARReasoningStep,
    SOARTrigger,
)
from shieldops.agents.intelligent_soar.prompts import (
    SYSTEM_ADAPT_EXECUTION,
    SYSTEM_PLAYBOOK_SELECTION,
    SYSTEM_TRIGGER_ANALYSIS,
    SYSTEM_VALIDATE_OUTCOME,
    AdaptationOutput,
    OutcomeAssessmentOutput,
    PlaybookSelectionOutput,
    TriggerAnalysisOutput,
)
from shieldops.agents.intelligent_soar.tools import (
    IntelligentSOARToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: IntelligentSOARToolkit | None = None


def set_toolkit(
    toolkit: IntelligentSOARToolkit,
) -> None:
    """Set the shared toolkit instance."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> IntelligentSOARToolkit:
    if _toolkit is None:
        return IntelligentSOARToolkit()
    return _toolkit


async def receive_trigger(
    state: IntelligentSOARState,
) -> dict[str, Any]:
    """Receive and analyze the incoming trigger."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("receive_trigger", 1.0)

    trigger = state.trigger or SOARTrigger()
    trigger_data = trigger.model_dump(mode="json")

    ingested = await toolkit.ingest_trigger(trigger_data)

    # LLM: classify trigger with deeper analysis
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "trigger": trigger_data,
                "ingested": ingested,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_TRIGGER_ANALYSIS,
            user_prompt=(f"Analyze this SOAR trigger:\n{ctx}"),
            schema=TriggerAnalysisOutput,
        )
        enriched_trigger = SOARTrigger(
            trigger_id=trigger.trigger_id,
            source=trigger.source,
            alert_type=getattr(llm_result, "alert_type", ""),
            severity=getattr(llm_result, "severity", "medium"),
            raw_payload=trigger.raw_payload,
            indicators=getattr(llm_result, "indicators", []),
            timestamp=trigger.timestamp,
        )
        logger.info(
            "llm_enhanced",
            node="receive_trigger",
            severity=enriched_trigger.severity,
        )
    except Exception:
        enriched_trigger = trigger
        logger.debug(
            "llm_enhancement_skipped",
            node="receive_trigger",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = SOARReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="receive_trigger",
        input_summary=(f"Trigger from {enriched_trigger.source}"),
        output_summary=(f"Classified as {enriched_trigger.severity}"),
        duration_ms=elapsed,
        tool_used="ingest_trigger",
    )

    return {
        "trigger": enriched_trigger,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "receive_trigger",
        "session_start": start,
    }


async def select_playbook(
    state: IntelligentSOARState,
) -> dict[str, Any]:
    """Select the best playbook via LLM ranking."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("select_playbook", 1.0)

    trigger = state.trigger or SOARTrigger()
    candidates = await toolkit.select_playbook(
        alert_type=trigger.alert_type,
        severity=trigger.severity,
        indicators=trigger.indicators,
    )

    # LLM: intelligent playbook selection
    selected = PlaybookSelection()
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "trigger": trigger.model_dump(mode="json"),
                "candidates": candidates,
                "execution_mode": state.execution_mode,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PLAYBOOK_SELECTION,
            user_prompt=(f"Select playbook:\n{ctx}"),
            schema=PlaybookSelectionOutput,
        )
        selected = PlaybookSelection(
            playbook_id=getattr(llm_result, "playbook_id", ""),
            playbook_name=getattr(llm_result, "playbook_id", ""),
            playbook_type=getattr(llm_result, "playbook_type", ""),
            match_score=getattr(llm_result, "match_score", 0.0),
            reasoning=getattr(llm_result, "reasoning", ""),
            requires_approval=getattr(llm_result, "requires_approval", False),
        )
        logger.info(
            "llm_enhanced",
            node="select_playbook",
            playbook=selected.playbook_id,
        )
    except Exception:
        if candidates:
            top = candidates[0]
            selected = PlaybookSelection(
                playbook_id=top["playbook_id"],
                playbook_name=top["playbook_name"],
                playbook_type=top["playbook_type"],
                match_score=top["match_score"],
            )
        logger.debug(
            "llm_enhancement_skipped",
            node="select_playbook",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = SOARReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="select_playbook",
        input_summary=(f"{len(candidates)} candidates ranked"),
        output_summary=(f"Selected {selected.playbook_id}"),
        duration_ms=elapsed,
        tool_used="select_playbook",
    )

    return {
        "selected_playbook": selected,
        "playbooks_executed": (state.playbooks_executed + 1),
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "select_playbook",
    }


async def execute_steps(
    state: IntelligentSOARState,
) -> dict[str, Any]:
    """Execute playbook steps with vendor routing."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("execute_steps", 1.0)

    pb = state.selected_playbook or PlaybookSelection()
    trigger = state.trigger or SOARTrigger()

    # Look up playbook steps from registry
    pb_registry = toolkit._playbook_registry
    pb_def = pb_registry.get(pb.playbook_id, {})
    step_names = pb_def.get(
        "steps",
        [
            "investigate",
            "contain",
            "validate",
        ],
    )

    exec_steps: list[ExecutionStep] = []
    for i, step_name in enumerate(step_names):
        result = await toolkit.execute_step(
            step_name=step_name,
            target=trigger.source or "unknown",
            vendor="shieldops",
            execution_mode=state.execution_mode,
            params={
                "trigger_id": trigger.trigger_id,
            },
        )
        exec_steps.append(
            ExecutionStep(
                step_id=f"step-{i + 1}",
                step_name=step_name,
                action_type=result.get("step_name", step_name),
                target=result.get("target", "unknown"),
                vendor=result.get("vendor", "shieldops"),
                status=result.get("status", "completed"),
                result=result.get("result", {}),
            )
        )

    completed = sum(1 for s in exec_steps if s.status in ("completed", "simulated"))

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = SOARReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_steps",
        input_summary=(f"{len(step_names)} steps to execute"),
        output_summary=(f"{completed}/{len(step_names)} completed"),
        duration_ms=elapsed,
        tool_used="execute_step",
    )

    return {
        "execution_steps": exec_steps,
        "steps_completed": completed,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_steps",
    }


async def adapt_dynamically(
    state: IntelligentSOARState,
) -> dict[str, Any]:
    """Adapt playbook mid-execution based on findings.

    This is the core differentiator vs XSOAR:
    LangGraph playbooks can reason and adapt in
    real-time based on intermediate results.
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("adapt_dynamically", 1.0)

    completed_results = [s.model_dump(mode="json") for s in state.execution_steps]
    findings: dict[str, Any] = {
        "anomalies": [],
        "escalation": False,
    }

    adaptation_ctx = await toolkit.evaluate_adaptation(
        completed_steps=completed_results,
        remaining_steps=[],
        findings=findings,
    )

    decisions: list[AdaptiveDecision] = []

    # LLM: decide if adaptation is needed
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "adaptation_context": adaptation_ctx,
                "trigger": (state.trigger.model_dump(mode="json") if state.trigger else {}),
                "steps_completed": (state.steps_completed),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ADAPT_EXECUTION,
            user_prompt=(f"Evaluate adaptation:\n{ctx}"),
            schema=AdaptationOutput,
        )
        if getattr(llm_result, "should_adapt", False):
            decisions.append(
                AdaptiveDecision(
                    decision_id=(f"adapt-{len(decisions) + 1}"),
                    trigger_finding=getattr(llm_result, "reasoning", ""),
                    original_step="current",
                    adapted_step=getattr(
                        llm_result,
                        "adapted_action",
                        "",
                    ),
                    reasoning=getattr(llm_result, "reasoning", ""),
                    confidence=getattr(llm_result, "confidence", 0.0),
                )
            )
        logger.info(
            "llm_enhanced",
            node="adapt_dynamically",
            adapted=len(decisions) > 0,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="adapt_dynamically",
        )

    total_steps = len(state.execution_steps) or 1
    rate = round(len(decisions) / total_steps, 3)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = SOARReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="adapt_dynamically",
        input_summary=(f"Evaluating {total_steps} step results"),
        output_summary=(f"{len(decisions)} adaptations made"),
        duration_ms=elapsed,
        tool_used="evaluate_adaptation",
    )

    return {
        "adaptive_decisions": [
            *state.adaptive_decisions,
            *decisions,
        ],
        "adaptation_rate": rate,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "adapt_dynamically",
    }


async def validate_outcome(
    state: IntelligentSOARState,
) -> dict[str, Any]:
    """Validate playbook outcome and residual risk."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("validate_outcome", 1.0)

    trigger = state.trigger or SOARTrigger()
    exec_results = [s.model_dump(mode="json") for s in state.execution_steps]

    validation = await toolkit.validate_outcome(
        execution_results=exec_results,
        trigger_indicators=trigger.indicators,
    )

    # LLM: deeper outcome assessment
    outcome = OutcomeValidation()
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "validation": validation,
                "trigger": trigger.model_dump(mode="json"),
                "steps_completed": (state.steps_completed),
                "adaptations": len(state.adaptive_decisions),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VALIDATE_OUTCOME,
            user_prompt=(f"Validate outcome:\n{ctx}"),
            schema=OutcomeAssessmentOutput,
        )
        outcome = OutcomeValidation(
            validated=True,
            threat_neutralized=getattr(
                llm_result,
                "threat_neutralized",
                False,
            ),
            residual_risk=getattr(llm_result, "residual_risk", 1.0),
            recommendations=getattr(llm_result, "recommendations", []),
        )
        logger.info(
            "llm_enhanced",
            node="validate_outcome",
            neutralized=(outcome.threat_neutralized),
        )
    except Exception:
        outcome = OutcomeValidation(
            validated=validation.get("validated", False),
            threat_neutralized=validation.get("success_rate", 0) > 0.8,
            residual_risk=1.0 - validation.get("success_rate", 0),
        )
        logger.debug(
            "llm_enhancement_skipped",
            node="validate_outcome",
        )

    # Track effectiveness for learning
    pb = state.selected_playbook
    if pb:
        await toolkit.track_effectiveness(
            playbook_id=pb.playbook_id,
            success_rate=validation.get("success_rate", 0.0),
            adaptation_count=len(state.adaptive_decisions),
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = SOARReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="validate_outcome",
        input_summary=(f"Validating {len(exec_results)} steps"),
        output_summary=(f"Threat neutralized: {outcome.threat_neutralized}"),
        duration_ms=elapsed,
        tool_used="validate_outcome",
    )

    return {
        "outcomes": outcome,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_outcome",
    }


async def report(
    state: IntelligentSOARState,
) -> dict[str, Any]:
    """Finalize the SOAR session and report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    await toolkit.record_metric(
        "intelligent_soar_duration_ms",
        float(duration_ms),
    )
    await toolkit.record_metric(
        "steps_completed",
        float(state.steps_completed),
    )
    await toolkit.record_metric(
        "adaptation_rate",
        state.adaptation_rate,
    )

    step = SOARReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report",
        input_summary="Finalizing SOAR session",
        output_summary=(f"Session complete in {duration_ms}ms"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    return {
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
