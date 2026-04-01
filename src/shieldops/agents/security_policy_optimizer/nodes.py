"""Node implementations for the Security Policy Optimizer."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_policy_optimizer.models import (
    ReasoningStep,
    SecurityPolicyOptimizerState,
    SPOStage,
)
from shieldops.agents.security_policy_optimizer.prompts import (
    SYSTEM_ANALYZE_EFFECTIVENESS,
    SYSTEM_APPLY_CHANGES,
    SYSTEM_COLLECT_POLICIES,
    SYSTEM_IDENTIFY_OPTIMIZATIONS,
    SYSTEM_VALIDATE_CHANGES,
    ChangeApplicationOutput,
    ChangeValidationOutput,
    EffectivenessAnalysisOutput,
    OptimizationIdentificationOutput,
    PolicyCollectionOutput,
)
from shieldops.agents.security_policy_optimizer.tools import (
    SecurityPolicyOptimizerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityPolicyOptimizerToolkit | None = None


def set_toolkit(
    toolkit: SecurityPolicyOptimizerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityPolicyOptimizerToolkit:
    if _toolkit is None:
        return SecurityPolicyOptimizerToolkit()
    return _toolkit


def _step(
    state: SecurityPolicyOptimizerState,
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


async def collect_policies(
    state: SecurityPolicyOptimizerState,
) -> dict[str, Any]:
    """Collect security policies from configured sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.collect_policies(state.config)
    enabled = sum(1 for p in raw if p.get("enabled", False))

    try:
        ctx = _json.dumps(
            {"sources": state.config.get("sources", []), "policy_count": len(raw)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COLLECT_POLICIES,
            user_prompt=f"Policy collection context:\n{ctx}",
            schema=PolicyCollectionOutput,
        )
        if hasattr(llm_result, "total_policies"):
            logger.info("llm_enhanced", node="collect_policies")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="collect_policies")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "collect_policies",
        f"sources={state.config.get('sources', [])}",
        f"collected {len(raw)} policies, {enabled} enabled",
        elapsed,
        "policy_store",
    )
    await toolkit.record_metric("policies_collected", float(len(raw)))

    return {
        "policies": raw,
        "stage": SPOStage.ANALYZE_EFFECTIVENESS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_policies",
        "session_start": start,
    }


async def analyze_effectiveness(
    state: SecurityPolicyOptimizerState,
) -> dict[str, Any]:
    """Analyze effectiveness of collected policies using telemetry."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    metrics = await toolkit.analyze_effectiveness(state.policies)
    high_fp = sum(1 for m in metrics if m.get("precision", 1.0) < 0.5)

    try:
        ctx = _json.dumps(
            {"policy_count": len(state.policies), "metrics_count": len(metrics)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ANALYZE_EFFECTIVENESS,
            user_prompt=f"Effectiveness analysis context:\n{ctx}",
            schema=EffectivenessAnalysisOutput,
        )
        if hasattr(llm_result, "high_fp_count"):
            logger.info("llm_enhanced", node="analyze_effectiveness")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="analyze_effectiveness")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "analyze_effectiveness",
        f"analyzing {len(state.policies)} policies",
        f"{len(metrics)} metrics, {high_fp} high-FP rules",
        elapsed,
        "telemetry_client",
    )

    return {
        "effectiveness": metrics,
        "stage": SPOStage.IDENTIFY_OPTIMIZATIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_effectiveness",
    }


async def identify_optimizations(
    state: SecurityPolicyOptimizerState,
) -> dict[str, Any]:
    """Identify optimization opportunities from effectiveness data."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    opts = await toolkit.identify_optimizations(state.policies, state.effectiveness)

    try:
        ctx = _json.dumps(
            {"effectiveness_count": len(state.effectiveness), "optimizations": len(opts)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_IDENTIFY_OPTIMIZATIONS,
            user_prompt=f"Optimization identification context:\n{ctx}",
            schema=OptimizationIdentificationOutput,
        )
        if hasattr(llm_result, "optimizations_found"):
            logger.info("llm_enhanced", node="identify_optimizations")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="identify_optimizations")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "identify_optimizations",
        f"evaluating {len(state.effectiveness)} metrics",
        f"identified {len(opts)} optimizations",
        elapsed,
        "policy_engine",
    )
    await toolkit.record_metric("optimizations_identified", float(len(opts)))

    return {
        "optimizations": opts,
        "stage": SPOStage.APPLY_CHANGES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_optimizations",
    }


async def apply_changes(
    state: SecurityPolicyOptimizerState,
) -> dict[str, Any]:
    """Apply policy changes based on optimization recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    changes = await toolkit.apply_changes(state.optimizations, state.config)
    applied = sum(1 for c in changes if c.get("applied", False))

    try:
        ctx = _json.dumps(
            {"optimization_count": len(state.optimizations), "changes_applied": applied},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_APPLY_CHANGES,
            user_prompt=f"Change application context:\n{ctx}",
            schema=ChangeApplicationOutput,
        )
        if hasattr(llm_result, "changes_applied"):
            logger.info("llm_enhanced", node="apply_changes")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="apply_changes")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "apply_changes",
        f"applying {len(state.optimizations)} optimizations",
        f"{applied}/{len(changes)} changes applied",
        elapsed,
        "policy_engine",
    )

    return {
        "changes": changes,
        "stage": SPOStage.VALIDATE_CHANGES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "apply_changes",
    }


async def validate_changes(
    state: SecurityPolicyOptimizerState,
) -> dict[str, Any]:
    """Validate applied policy changes against telemetry."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    validations = await toolkit.validate_changes(state.changes)
    passed = sum(1 for v in validations if v.get("passed", False))

    try:
        ctx = _json.dumps(
            {"change_count": len(state.changes), "validations": len(validations)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VALIDATE_CHANGES,
            user_prompt=f"Change validation context:\n{ctx}",
            schema=ChangeValidationOutput,
        )
        if hasattr(llm_result, "validations_passed"):
            logger.info("llm_enhanced", node="validate_changes")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="validate_changes")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "validate_changes",
        f"validating {len(state.changes)} changes",
        f"{passed}/{len(validations)} validations passed",
        elapsed,
        "telemetry_client",
    )

    return {
        "validations": validations,
        "stage": SPOStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_changes",
    }


async def generate_report(
    state: SecurityPolicyOptimizerState,
) -> dict[str, Any]:
    """Generate final policy optimization report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    applied = sum(1 for c in state.changes if c.get("applied", False))
    passed = sum(1 for v in state.validations if v.get("passed", False))

    report = {
        "request_id": state.request_id,
        "policies_analyzed": len(state.policies),
        "effectiveness_metrics": len(state.effectiveness),
        "optimizations_identified": len(state.optimizations),
        "changes_applied": applied,
        "validations_passed": passed,
        "validations_failed": len(state.validations) - passed,
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("scan_duration_ms", float(duration_ms))

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
