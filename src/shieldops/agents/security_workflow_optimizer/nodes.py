"""Node implementations for the Security Workflow Optimizer."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_workflow_optimizer.models import (
    ReasoningStep,
    SecurityWorkflowOptimizerState,
    SWOStage,
)
from shieldops.agents.security_workflow_optimizer.prompts import (
    SYSTEM_ANALYZE_PATTERNS,
    SYSTEM_COLLECT_WORKFLOWS,
    SYSTEM_IDENTIFY_BOTTLENECKS,
    SYSTEM_OPTIMIZE_PATHS,
    SYSTEM_VALIDATE,
    BottleneckOutput,
    OptimizationOutput,
    PatternAnalysisOutput,
    ValidationOutput,
    WorkflowCollectionOutput,
)
from shieldops.agents.security_workflow_optimizer.tools import (
    SecurityWorkflowOptimizerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityWorkflowOptimizerToolkit | None = None


def _get_toolkit() -> SecurityWorkflowOptimizerToolkit:
    if _toolkit is None:
        return SecurityWorkflowOptimizerToolkit()
    return _toolkit


def _step(
    state: SecurityWorkflowOptimizerState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Create a reasoning step."""
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def collect_workflows(
    state: SecurityWorkflowOptimizerState,
) -> dict[str, Any]:
    """Collect security workflows for analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.collect_workflows(state.config)

    try:
        ctx = _json.dumps(
            {
                "categories": state.config.get("categories", []),
                "workflow_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COLLECT_WORKFLOWS,
            user_prompt=f"Workflow collection context:\n{ctx}",
            schema=WorkflowCollectionOutput,
        )
        if hasattr(llm_result, "total_workflows"):
            logger.info("llm_enhanced", node="collect_workflows")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="collect_workflows")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "collect_workflows",
        f"config={state.config}",
        f"collected {len(raw)} workflows",
        elapsed,
        "workflow_client",
    )
    await toolkit.record_metric("workflows_collected", float(len(raw)))

    return {
        "workflows": raw,
        "stage": SWOStage.ANALYZE_PATTERNS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_workflows",
        "session_start": start,
    }


async def analyze_patterns(
    state: SecurityWorkflowOptimizerState,
) -> dict[str, Any]:
    """Analyze execution patterns across workflows."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    patterns = await toolkit.analyze_patterns(state.workflows)
    high_lat = sum(1 for p in patterns if p.get("avg_latency_ms", 0) > 5000)

    try:
        ctx = _json.dumps(
            {
                "workflow_count": len(state.workflows),
                "pattern_count": len(patterns),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ANALYZE_PATTERNS,
            user_prompt=f"Pattern analysis context:\n{ctx}",
            schema=PatternAnalysisOutput,
        )
        if hasattr(llm_result, "total_patterns"):
            logger.info("llm_enhanced", node="analyze_patterns")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="analyze_patterns")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "analyze_patterns",
        f"analyzing {len(state.workflows)} workflows",
        f"{len(patterns)} patterns, {high_lat} high-latency",
        elapsed,
        "analytics_client",
    )

    return {
        "patterns": patterns,
        "stage": SWOStage.IDENTIFY_BOTTLENECKS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_patterns",
    }


async def identify_bottlenecks(
    state: SecurityWorkflowOptimizerState,
) -> dict[str, Any]:
    """Identify bottlenecks from pattern analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    bottlenecks = await toolkit.identify_bottlenecks(state.patterns)

    try:
        ctx = _json.dumps(
            {
                "pattern_count": len(state.patterns),
                "bottleneck_count": len(bottlenecks),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_IDENTIFY_BOTTLENECKS,
            user_prompt=f"Bottleneck context:\n{ctx}",
            schema=BottleneckOutput,
        )
        if hasattr(llm_result, "bottlenecks_found"):
            logger.info("llm_enhanced", node="identify_bottlenecks")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="identify_bottlenecks")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "identify_bottlenecks",
        f"analyzing {len(state.patterns)} patterns",
        f"found {len(bottlenecks)} bottlenecks",
        elapsed,
        "analytics_client",
    )
    await toolkit.record_metric("bottlenecks_found", float(len(bottlenecks)))

    return {
        "bottlenecks": bottlenecks,
        "stage": SWOStage.OPTIMIZE_PATHS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_bottlenecks",
    }


async def optimize_paths(
    state: SecurityWorkflowOptimizerState,
) -> dict[str, Any]:
    """Apply optimizations to bottlenecked workflows."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    optimizations = await toolkit.optimize_paths(state.bottlenecks, state.config)

    try:
        ctx = _json.dumps(
            {
                "bottleneck_count": len(state.bottlenecks),
                "optimization_count": len(optimizations),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_OPTIMIZE_PATHS,
            user_prompt=f"Optimization context:\n{ctx}",
            schema=OptimizationOutput,
        )
        if hasattr(llm_result, "optimizations_applied"):
            logger.info("llm_enhanced", node="optimize_paths")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="optimize_paths")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "optimize_paths",
        f"optimizing {len(state.bottlenecks)} bottlenecks",
        f"applied {len(optimizations)} optimizations",
        elapsed,
        "optimizer_engine",
    )

    return {
        "optimizations": optimizations,
        "stage": SWOStage.VALIDATE_IMPROVEMENTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "optimize_paths",
    }


async def validate_improvements(
    state: SecurityWorkflowOptimizerState,
) -> dict[str, Any]:
    """Validate that optimizations are safe and effective."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    validations = await toolkit.validate_improvements(state.optimizations)

    try:
        ctx = _json.dumps(
            {
                "optimization_count": len(state.optimizations),
                "validations": validations[:5],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VALIDATE,
            user_prompt=f"Validation context:\n{ctx}",
            schema=ValidationOutput,
        )
        if hasattr(llm_result, "tests_passed"):
            logger.info("llm_enhanced", node="validate_improvements")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="validate_improvements")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "validate_improvements",
        f"validating {len(state.optimizations)} optimizations",
        f"{len(validations)} validation results",
        elapsed,
        "optimizer_engine",
    )

    return {
        "validations": validations,
        "stage": SWOStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_improvements",
    }


async def generate_report(
    state: SecurityWorkflowOptimizerState,
) -> dict[str, Any]:
    """Generate final workflow optimization report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "workflows": len(state.workflows),
        "patterns": len(state.patterns),
        "bottlenecks": len(state.bottlenecks),
        "optimizations": len(state.optimizations),
        "validations": len(state.validations),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("optimization_duration_ms", float(duration_ms))

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
