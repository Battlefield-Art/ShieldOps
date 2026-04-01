"""Node implementations for the Security Chaos Orchestrator."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_chaos_orchestrator.models import (
    ReasoningStep,
    SCOStage,
    SecurityChaosOrchestratorState,
)
from shieldops.agents.security_chaos_orchestrator.prompts import (
    SYSTEM_ANALYZE_RESILIENCE,
    SYSTEM_DEFINE_BLAST_RADIUS,
    SYSTEM_INJECT_FAILURES,
    SYSTEM_OBSERVE_BEHAVIOR,
    SYSTEM_PLAN_EXPERIMENTS,
    BlastRadiusOutput,
    ExperimentPlanOutput,
    FailureInjectionOutput,
    ObservationOutput,
    ResilienceOutput,
)
from shieldops.agents.security_chaos_orchestrator.tools import (
    SecurityChaosOrchestratorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityChaosOrchestratorToolkit | None = None


def set_toolkit(
    toolkit: SecurityChaosOrchestratorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityChaosOrchestratorToolkit:
    if _toolkit is None:
        return SecurityChaosOrchestratorToolkit()
    return _toolkit


def _step(
    state: SecurityChaosOrchestratorState,
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


async def plan_experiments(
    state: SecurityChaosOrchestratorState,
) -> dict[str, Any]:
    """Plan chaos experiments for security controls."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.plan_experiments(state.config)
    high_risk = sum(1 for e in raw if e.get("risk_score", 0) > 0.7)

    try:
        ctx = _json.dumps(
            {
                "targets": state.config.get("targets", []),
                "experiment_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PLAN_EXPERIMENTS,
            user_prompt=f"Experiment planning context:\n{ctx}",
            schema=ExperimentPlanOutput,
        )
        if hasattr(llm_result, "total_experiments"):
            logger.info("llm_enhanced", node="plan_experiments")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="plan_experiments")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "plan_experiments",
        f"targets={state.config.get('targets', [])}",
        f"planned {len(raw)} experiments, {high_risk} high-risk",
        elapsed,
        "chaos_client",
    )
    await toolkit.record_metric("experiments_planned", float(len(raw)))

    return {
        "experiments": raw,
        "stage": SCOStage.DEFINE_BLAST_RADIUS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "plan_experiments",
        "session_start": start,
    }


async def define_blast_radius(
    state: SecurityChaosOrchestratorState,
) -> dict[str, Any]:
    """Define blast radius for each experiment."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    radii = await toolkit.define_blast_radius(state.experiments)
    approved = sum(1 for r in radii if r.get("approved"))

    try:
        ctx = _json.dumps(
            {
                "experiment_count": len(state.experiments),
                "radii_count": len(radii),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DEFINE_BLAST_RADIUS,
            user_prompt=f"Blast radius context:\n{ctx}",
            schema=BlastRadiusOutput,
        )
        if hasattr(llm_result, "total_services_affected"):
            logger.info("llm_enhanced", node="define_blast_radius")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="define_blast_radius",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "define_blast_radius",
        f"defining for {len(state.experiments)} experiments",
        f"{len(radii)} radii, {approved} approved",
        elapsed,
        "service_registry",
    )

    return {
        "blast_radii": radii,
        "stage": SCOStage.INJECT_FAILURES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "define_blast_radius",
    }


async def inject_failures(
    state: SecurityChaosOrchestratorState,
) -> dict[str, Any]:
    """Inject failures for approved experiments."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    injections = await toolkit.inject_failures(state.experiments, state.blast_radii)

    try:
        ctx = _json.dumps(
            {
                "experiment_count": len(state.experiments),
                "injection_count": len(injections),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_INJECT_FAILURES,
            user_prompt=f"Failure injection context:\n{ctx}",
            schema=FailureInjectionOutput,
        )
        if hasattr(llm_result, "injections_executed"):
            logger.info("llm_enhanced", node="inject_failures")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="inject_failures")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "inject_failures",
        f"injecting into {len(state.experiments)} experiments",
        f"{len(injections)} failures injected",
        elapsed,
        "chaos_client",
    )
    await toolkit.record_metric("failures_injected", float(len(injections)))

    return {
        "injections": injections,
        "stage": SCOStage.OBSERVE_BEHAVIOR,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "inject_failures",
    }


async def observe_behavior(
    state: SecurityChaosOrchestratorState,
) -> dict[str, Any]:
    """Observe system behavior during failure injection."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    observations = await toolkit.observe_behavior(state.injections)
    anomalies = sum(1 for o in observations if abs(o.get("deviation_pct", 0)) > 30)

    try:
        ctx = _json.dumps(
            {
                "injection_count": len(state.injections),
                "observation_count": len(observations),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_OBSERVE_BEHAVIOR,
            user_prompt=f"Behavior observation context:\n{ctx}",
            schema=ObservationOutput,
        )
        if hasattr(llm_result, "anomalies_detected"):
            logger.info("llm_enhanced", node="observe_behavior")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="observe_behavior",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "observe_behavior",
        f"observing {len(state.injections)} injections",
        f"{len(observations)} observations, {anomalies} anomalies",
        elapsed,
        "monitoring_client",
    )

    return {
        "observations": observations,
        "stage": SCOStage.ANALYZE_RESILIENCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "observe_behavior",
    }


async def analyze_resilience(
    state: SecurityChaosOrchestratorState,
) -> dict[str, Any]:
    """Analyze resilience based on observations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.analyze_resilience(state.observations, state.experiments)
    fragile = sum(1 for a in assessments if a.get("resilience_level") in ("fragile", "critical"))

    try:
        ctx = _json.dumps(
            {
                "observation_count": len(state.observations),
                "assessment_count": len(assessments),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ANALYZE_RESILIENCE,
            user_prompt=f"Resilience analysis context:\n{ctx}",
            schema=ResilienceOutput,
        )
        if hasattr(llm_result, "fragile_count"):
            logger.info("llm_enhanced", node="analyze_resilience")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_resilience",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "analyze_resilience",
        f"analyzing {len(state.observations)} observations",
        f"{len(assessments)} assessments, {fragile} fragile",
        elapsed,
        "chaos_client",
    )

    return {
        "assessments": assessments,
        "stage": SCOStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_resilience",
    }


async def generate_report(
    state: SecurityChaosOrchestratorState,
) -> dict[str, Any]:
    """Generate final chaos orchestration report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "experiments": len(state.experiments),
        "blast_radii": len(state.blast_radii),
        "injections": len(state.injections),
        "observations": len(state.observations),
        "assessments": len(state.assessments),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("chaos_duration_ms", float(duration_ms))

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
