"""Node implementations for the Attack Replay Simulator LangGraph workflow.

Each node is an async function that:
1. Queries replay systems via the toolkit
2. Uses the LLM to analyze and reason about data
3. Updates the ARS state with findings
4. Records its reasoning step in the audit trail
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.attack_replay_simulator.models import (
    ARSStage,
    AttackReplaySimulatorState,
    DetectionResult,
    ReasoningStep,
    ReplayExecution,
    SandboxConfig,
    TechniqueSelection,
    TelemetryCapture,
)
from shieldops.agents.attack_replay_simulator.prompts import (
    SYSTEM_CAPTURE_TELEMETRY,
    SYSTEM_CONFIGURE_SANDBOX,
    SYSTEM_EVALUATE_DETECTION,
    SYSTEM_EXECUTE_REPLAY,
    SYSTEM_SELECT_TECHNIQUES,
    DetectionEvaluationAnalysis,
    ReplayExecutionAnalysis,
    SandboxConfigAnalysis,
    TechniqueSelectionAnalysis,
    TelemetryCaptureAnalysis,
)
from shieldops.agents.attack_replay_simulator.tools import (
    AttackReplaySimulatorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit, set by runner at startup.
_toolkit: AttackReplaySimulatorToolkit | None = None


def _get_toolkit() -> AttackReplaySimulatorToolkit:
    if _toolkit is None:
        return AttackReplaySimulatorToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# ---- Node: select_techniques ----


async def select_techniques(
    state: AttackReplaySimulatorState,
) -> dict[str, Any]:
    """Select attack techniques for replay simulation."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "ars_selecting_techniques",
        request_id=state.request_id,
    )

    filters = state.config.get("filters")
    selections = await toolkit.select_techniques(
        tenant_id=state.tenant_id,
        filters=filters,
    )

    output_summary = f"Selected {len(selections)} techniques for replay."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "techniques_selected": len(selections),
                "techniques": [s.technique.value for s in selections],
                "complexities": [s.complexity for s in selections],
            },
            default=str,
        )
        llm_result = cast(
            TechniqueSelectionAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_SELECT_TECHNIQUES,
                user_prompt=(f"Technique selection results:\n{ctx}"),
                schema=TechniqueSelectionAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(selections)} techniques."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="select_techniques",
        )

    step = ReasoningStep(
        step_number=1,
        action="select_techniques",
        input_summary="Selecting attack techniques for replay",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="technique_selector",
    )

    return {
        "techniques": [s.model_dump() for s in selections],
        "technique_count": len(selections),
        "stage": ARSStage.CONFIGURE_SANDBOX,
        "session_start": start,
        "reasoning_chain": [step],
        "current_step": "select_techniques",
    }


# ---- Node: configure_sandbox ----


async def configure_sandbox(
    state: AttackReplaySimulatorState,
) -> dict[str, Any]:
    """Configure sandbox environment for replay."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    techniques = [TechniqueSelection.model_validate(t) for t in state.techniques]

    logger.info(
        "ars_configuring_sandbox",
        request_id=state.request_id,
        technique_count=len(techniques),
    )

    sandbox = await toolkit.configure_sandbox(techniques)

    output_summary = (
        f"Sandbox {sandbox.sandbox_id} configured "
        f"with {len(sandbox.detection_tools)} detection tools."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "sandbox_id": sandbox.sandbox_id,
                "os_type": sandbox.os_type,
                "detection_tools": sandbox.detection_tools,
                "techniques": len(techniques),
            },
            default=str,
        )
        llm_result = cast(
            SandboxConfigAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_CONFIGURE_SANDBOX,
                user_prompt=(f"Sandbox configuration results:\n{ctx}"),
                schema=SandboxConfigAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Readiness: {llm_result.readiness}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="configure_sandbox",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="configure_sandbox",
        input_summary=(f"Configuring sandbox for {len(techniques)} techniques"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="sandbox_configurator",
    )

    return {
        "sandbox": sandbox.model_dump(),
        "stage": ARSStage.EXECUTE_REPLAY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "configure_sandbox",
    }


# ---- Node: execute_replay ----


async def execute_replay(
    state: AttackReplaySimulatorState,
) -> dict[str, Any]:
    """Execute attack technique replays in sandbox."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    techniques = [TechniqueSelection.model_validate(t) for t in state.techniques]
    sandbox = SandboxConfig.model_validate(state.sandbox)

    logger.info(
        "ars_executing_replay",
        request_id=state.request_id,
        technique_count=len(techniques),
        sandbox_id=sandbox.sandbox_id,
    )

    executions = await toolkit.execute_replay(
        techniques,
        sandbox,
    )

    output_summary = (
        f"Executed {len(executions)} technique replays in sandbox {sandbox.sandbox_id}."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "executions": len(executions),
                "sandbox": sandbox.sandbox_id,
                "techniques": [e.technique.value for e in executions],
                "exit_codes": [e.exit_code for e in executions],
            },
            default=str,
        )
        llm_result = cast(
            ReplayExecutionAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_EXECUTE_REPLAY,
                user_prompt=(f"Replay execution results:\n{ctx}"),
                schema=ReplayExecutionAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Quality: {llm_result.execution_quality}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="execute_replay",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_replay",
        input_summary=(f"Executing {len(techniques)} replays in {sandbox.sandbox_id}"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="replay_executor",
    )

    return {
        "executions": [e.model_dump() for e in executions],
        "stage": ARSStage.CAPTURE_TELEMETRY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_replay",
    }


# ---- Node: capture_telemetry ----


async def capture_telemetry(
    state: AttackReplaySimulatorState,
) -> dict[str, Any]:
    """Capture telemetry from replay executions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    executions = [ReplayExecution.model_validate(e) for e in state.executions]

    logger.info(
        "ars_capturing_telemetry",
        request_id=state.request_id,
        execution_count=len(executions),
    )

    captures = await toolkit.capture_telemetry(executions)
    total_alerts = sum(c.alerts_fired for c in captures)

    output_summary = (
        f"Captured telemetry from {len(captures)} executions. {total_alerts} alerts fired."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "captures": len(captures),
                "total_alerts": total_alerts,
                "total_logs": sum(c.logs_generated for c in captures),
                "total_network_events": sum(c.network_events for c in captures),
            },
            default=str,
        )
        llm_result = cast(
            TelemetryCaptureAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_CAPTURE_TELEMETRY,
                user_prompt=(f"Telemetry capture results:\n{ctx}"),
                schema=TelemetryCaptureAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {total_alerts} alerts fired."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="capture_telemetry",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="capture_telemetry",
        input_summary=(f"Capturing telemetry from {len(executions)} executions"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="telemetry_capturer",
    )

    return {
        "telemetry": [c.model_dump() for c in captures],
        "stage": ARSStage.EVALUATE_DETECTION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "capture_telemetry",
    }


# ---- Node: evaluate_detection ----


async def evaluate_detection(
    state: AttackReplaySimulatorState,
) -> dict[str, Any]:
    """Evaluate detection effectiveness."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    executions = [ReplayExecution.model_validate(e) for e in state.executions]
    captures = [TelemetryCapture.model_validate(t) for t in state.telemetry]

    logger.info(
        "ars_evaluating_detection",
        request_id=state.request_id,
        execution_count=len(executions),
    )

    evaluations = await toolkit.evaluate_detection(
        executions,
        captures,
    )

    detected = sum(
        1 for e in evaluations if e.result in (DetectionResult.DETECTED, DetectionResult.BLOCKED)
    )
    missed = sum(1 for e in evaluations if e.result == DetectionResult.MISSED)

    output_summary = (
        f"Evaluated {len(evaluations)} techniques. {detected} detected, {missed} missed."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "evaluations": len(evaluations),
                "detected": detected,
                "missed": missed,
                "results": [e.result.value for e in evaluations],
            },
            default=str,
        )
        llm_result = cast(
            DetectionEvaluationAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_EVALUATE_DETECTION,
                user_prompt=(f"Detection evaluation results:\n{ctx}"),
                schema=DetectionEvaluationAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Risk: {llm_result.risk_level}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="evaluate_detection",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="evaluate_detection",
        input_summary=(f"Evaluating detection for {len(evaluations)} techniques"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="detection_evaluator",
    )

    return {
        "evaluations": [e.model_dump() for e in evaluations],
        "detected_count": detected,
        "missed_count": missed,
        "stage": ARSStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "evaluate_detection",
    }


# ---- Node: generate_report ----


async def generate_report(
    state: AttackReplaySimulatorState,
) -> dict[str, Any]:
    """Final reporting node -- summarize the replay cycle."""
    start = datetime.now(UTC)

    session_duration_ms = 0
    if state.session_start:
        session_duration_ms = _elapsed_ms(state.session_start)

    output_summary = (
        f"ARS cycle complete. "
        f"{state.technique_count} techniques, "
        f"{len(state.executions)} executions, "
        f"{state.detected_count} detected, "
        f"{state.missed_count} missed. "
        f"Duration: {session_duration_ms}ms."
    )

    logger.info(
        "ars_report",
        request_id=state.request_id,
        summary=output_summary,
    )

    report = {
        "request_id": state.request_id,
        "tenant_id": state.tenant_id,
        "techniques_selected": state.technique_count,
        "executions_run": len(state.executions),
        "telemetry_captures": len(state.telemetry),
        "evaluations_completed": len(state.evaluations),
        "detected": state.detected_count,
        "missed": state.missed_count,
        "duration_ms": session_duration_ms,
        "summary": output_summary,
    }

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary="Generating final replay simulation report",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": session_duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
