"""Node implementations for the Chaos Engineering Agent LangGraph workflow.

Each node is an async function that:
1. Calls toolkit tools to interact with infrastructure
2. Uses the LLM to analyze observations and produce recommendations
3. Updates the chaos engineering state
4. Records its reasoning step in the audit trail
"""

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.chaos_engineering.models import (
    ChaosEngineeringState,
    ChaosStage,
    ExperimentStatus,
    ReasoningStep,
)
from shieldops.agents.chaos_engineering.prompts import (
    SYSTEM_ANALYZE_RESULTS,
    SYSTEM_GENERATE_REPORT,
    ExperimentAnalysisResult,
    ExperimentReportResult,
)
from shieldops.agents.chaos_engineering.tools import ChaosEngineeringToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit reference, set by the runner at graph construction time.
_toolkit: ChaosEngineeringToolkit | None = None


def set_toolkit(toolkit: ChaosEngineeringToolkit) -> None:
    """Configure the toolkit used by all nodes. Called once at startup."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> ChaosEngineeringToolkit:
    if _toolkit is None:
        return ChaosEngineeringToolkit()
    return _toolkit


async def plan_experiment(state: ChaosEngineeringState) -> dict[str, Any]:
    """Plan a chaos experiment from the library or custom parameters."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "chaos_planning_experiment",
        experiment_name=state.experiment_name,
        target=f"{state.target_namespace}/{state.target_service}",
    )

    experiment = await toolkit.plan_experiment(
        experiment_name=state.experiment_name,
        target_service=state.target_service,
        target_namespace=state.target_namespace,
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="plan_experiment",
        input_summary=f"Experiment: {state.experiment_name}, "
        f"target: {state.target_namespace}/{state.target_service}",
        output_summary=f"Planned {experiment.fault_type} experiment "
        f"({experiment.duration_sec}s, blast_radius={experiment.blast_radius})",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="experiment_library",
    )

    return {
        "experiment": experiment,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": ChaosStage.PLAN_EXPERIMENT,
    }


async def validate_safety(state: ChaosEngineeringState) -> dict[str, Any]:
    """Run safety checks before fault injection."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    if state.experiment is None:
        return {
            "error": "No experiment to validate — planning step failed.",
            "safety_passed": False,
            "current_stage": ChaosStage.VALIDATE_SAFETY,
        }

    checks = await toolkit.validate_safety(state.experiment)
    all_blocking_passed = all(c.passed for c in checks if c.blocking)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="validate_safety",
        input_summary=f"Experiment {state.experiment.id} — {len(checks)} checks",
        output_summary=f"Safety {'PASSED' if all_blocking_passed else 'FAILED'}: "
        + "; ".join(f"{c.check_name}={'pass' if c.passed else 'FAIL'}" for c in checks),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="opa_policy",
    )

    return {
        "safety_checks": checks,
        "safety_passed": all_blocking_passed,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": ChaosStage.VALIDATE_SAFETY,
    }


async def inject_fault(state: ChaosEngineeringState) -> dict[str, Any]:
    """Inject the fault into the target service."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    if state.experiment is None:
        return {"error": "No experiment defined.", "current_stage": ChaosStage.INJECT_FAULT}

    experiment = state.experiment.model_copy(update={"status": ExperimentStatus.RUNNING})
    injection = await toolkit.inject_fault(experiment)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="inject_fault",
        input_summary=f"Injecting {experiment.fault_type} into "
        f"{experiment.target_namespace}/{experiment.target_service}",
        output_summary=f"Fault injected (id={injection.id}), duration={experiment.duration_sec}s",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="chaos_mesh",
    )

    return {
        "experiment": experiment,
        "fault_injection": injection,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": ChaosStage.INJECT_FAULT,
    }


async def observe_impact(state: ChaosEngineeringState) -> dict[str, Any]:
    """Observe service metrics during and after fault injection."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    if state.experiment is None or state.fault_injection is None:
        return {
            "error": "Missing experiment or injection.",
            "current_stage": ChaosStage.OBSERVE_IMPACT,
        }

    observations = await toolkit.observe_impact(state.experiment, state.fault_injection)
    slo_breached = state.fault_injection.rollback_triggered

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="observe_impact",
        input_summary=f"Observing {len(observations)} metrics for experiment {state.experiment.id}",
        output_summary=f"Collected {len(observations)} observations. SLO breached: {slo_breached}.",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="prometheus",
    )

    return {
        "observations": observations,
        "slo_breached": slo_breached,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": ChaosStage.OBSERVE_IMPACT,
    }


async def analyze_results(state: ChaosEngineeringState) -> dict[str, Any]:
    """Analyze experiment results using the LLM."""
    start = datetime.now(UTC)

    if state.experiment is None:
        return {"error": "No experiment to analyze.", "current_stage": ChaosStage.ANALYZE_RESULTS}

    # Build context for the LLM
    obs_lines = []
    for obs in state.observations:
        obs_lines.append(
            f"- {obs.metric_name}: baseline={obs.baseline_value}, "
            f"during_fault={obs.during_fault_value}, "
            f"deviation={obs.deviation_pct}%, "
            f"recovered={obs.recovered}"
        )

    safety_lines = [
        f"- {c.check_name}: {'PASS' if c.passed else 'FAIL'} — {c.details}"
        for c in state.safety_checks
    ]

    context_lines = [
        "## Experiment",
        f"Name: {state.experiment.name}",
        f"Fault type: {state.experiment.fault_type}",
        f"Target: {state.experiment.target_namespace}/{state.experiment.target_service}",
        f"Duration: {state.experiment.duration_sec}s",
        f"Blast radius: {state.experiment.blast_radius}",
        f"Hypothesis: {state.experiment.hypothesis}",
        "",
        "## Safety Checks",
        *safety_lines,
        "",
        "## Impact Observations",
        *obs_lines,
        "",
        f"SLO breached: {state.slo_breached}",
        f"Auto-rollback triggered: "
        f"{state.fault_injection.rollback_triggered if state.fault_injection else False}",
    ]
    user_prompt = "\n".join(context_lines)

    # Defaults in case the LLM call fails
    hypothesis_validated = not state.slo_breached
    resilience_score = 0.5
    recommendations = ["Review metric deviations and improve fault tolerance."]
    analysis_summary = "Analysis completed with default values."

    try:
        result = cast(
            ExperimentAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE_RESULTS,
                user_prompt=user_prompt,
                schema=ExperimentAnalysisResult,
            ),
        )
        hypothesis_validated = result.hypothesis_validated
        resilience_score = result.resilience_score
        recommendations = result.recommendations
        analysis_summary = result.summary
    except Exception as e:
        logger.error("llm_analyze_results_failed", error=str(e))
        analysis_summary = f"LLM analysis failed: {e}"

    # Update experiment status
    final_status = (
        ExperimentStatus.COMPLETED if not state.slo_breached else ExperimentStatus.ROLLED_BACK
    )
    experiment = state.experiment.model_copy(update={"status": final_status})

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_results",
        input_summary=f"{len(state.observations)} observations, slo_breached={state.slo_breached}",
        output_summary=analysis_summary[:200],
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    return {
        "experiment": experiment,
        "hypothesis_validated": hypothesis_validated,
        "resilience_score": resilience_score,
        "recommendations": recommendations,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": ChaosStage.ANALYZE_RESULTS,
    }


async def generate_report(state: ChaosEngineeringState) -> dict[str, Any]:
    """Generate a final experiment report using the LLM."""
    start = datetime.now(UTC)

    if state.experiment is None:
        return {"error": "No experiment to report on.", "current_stage": ChaosStage.REPORT}

    context_lines = [
        f"Experiment: {state.experiment.name}",
        f"Fault type: {state.experiment.fault_type}",
        f"Target: {state.experiment.target_namespace}/{state.experiment.target_service}",
        f"Status: {state.experiment.status}",
        f"Hypothesis validated: {state.hypothesis_validated}",
        f"Resilience score: {state.resilience_score}",
        f"SLO breached: {state.slo_breached}",
        "",
        "Recommendations:",
        *[f"- {r}" for r in state.recommendations],
    ]
    user_prompt = "\n".join(context_lines)

    report_summary = (
        f"Chaos experiment '{state.experiment.name}' "
        f"({'PASSED' if state.hypothesis_validated else 'FAILED'}). "
        f"Resilience score: {state.resilience_score:.2f}."
    )

    try:
        result = cast(
            ExperimentReportResult,
            await llm_structured(
                system_prompt=SYSTEM_GENERATE_REPORT,
                user_prompt=user_prompt,
                schema=ExperimentReportResult,
            ),
        )
        report_summary = (
            f"{result.title}\n\n"
            f"{result.executive_summary}\n\n"
            f"Risk: {result.risk_assessment}. "
            f"Follow-up: {'; '.join(result.follow_up_experiments)}"
        )
    except Exception as e:
        logger.error("llm_generate_report_failed", error=str(e))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=f"Experiment {state.experiment.id}, score={state.resilience_score:.2f}",
        output_summary=report_summary[:200],
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    total_duration = sum(s.duration_ms for s in [*state.reasoning_chain, step])

    return {
        "report_summary": report_summary,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": ChaosStage.REPORT,
        "duration_ms": total_duration,
    }


async def abort_experiment(state: ChaosEngineeringState) -> dict[str, Any]:
    """Abort the experiment when safety checks fail."""
    start = datetime.now(UTC)

    failed_checks = [c for c in state.safety_checks if not c.passed and c.blocking]
    reasons = "; ".join(f"{c.check_name}: {c.details}" for c in failed_checks)

    experiment = None
    if state.experiment is not None:
        experiment = state.experiment.model_copy(update={"status": ExperimentStatus.ABORTED})

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="abort_experiment",
        input_summary=f"Safety failed: {len(failed_checks)} blocking checks",
        output_summary=f"Experiment aborted. Reasons: {reasons[:200]}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    logger.warning(
        "chaos_experiment_aborted",
        experiment_id=experiment.id if experiment else "unknown",
        reasons=reasons,
    )

    return {
        "experiment": experiment,
        "error": f"Safety checks failed: {reasons}",
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": ChaosStage.REPORT,
    }
