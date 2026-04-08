"""Node implementations for the Security Chaos Tester
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_chaos_tester.models import (
    ReasoningStep,
    SCTStage,
    SecurityChaosState,
)
from shieldops.agents.security_chaos_tester.prompts import (
    SYSTEM_BEHAVIOR_ANALYSIS,
    SYSTEM_EXPERIMENT_DESIGN,
    SYSTEM_REPORT,
    SYSTEM_RESILIENCE,
    BehaviorAnalysisOutput,
    ChaosReportOutput,
    ExperimentDesignOutput,
    ResilienceAssessmentOutput,
)
from shieldops.agents.security_chaos_tester.tools import (
    SecurityChaosToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityChaosToolkit | None = None


def _get_toolkit() -> SecurityChaosToolkit:
    if _toolkit is None:
        return SecurityChaosToolkit()
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
    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: define_experiment
# ------------------------------------------------------------------


async def define_experiment(
    state: SecurityChaosState,
) -> dict[str, Any]:
    """Define chaos experiments from fault types and
    target components."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    fault_types = [f.value for f in state.fault_types]
    experiments = await toolkit.define_experiment(
        fault_types=fault_types,
        targets=state.target_components,
        scope=state.scope,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "experiment_name": state.experiment_name,
                "fault_types": fault_types,
                "targets": state.target_components,
                "scope": state.scope,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_EXPERIMENT_DESIGN,
            user_prompt=(f"Design experiments for:\n{ctx}"),
            schema=ExperimentDesignOutput,
        )
        if llm_out.experiments:  # type: ignore[union-attr]
            experiments = [
                *experiments,
                *llm_out.experiments,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="define_experiment",
            count=len(llm_out.experiments),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="define_experiment",
        )

    step = _step(
        state.reasoning_chain,
        "define_experiment",
        (f"Faults: {len(fault_types)}, targets: {len(state.target_components)}"),
        f"Defined {len(experiments)} experiments",
        start,
        "experiment_designer",
    )

    return {
        "experiments": experiments,
        "total_experiments": len(experiments),
        "stage": SCTStage.DEFINE_EXPERIMENT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "define_experiment",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: inject_fault
# ------------------------------------------------------------------


async def inject_fault(
    state: SecurityChaosState,
) -> dict[str, Any]:
    """Inject security faults for each experiment."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    injections: list[dict[str, Any]] = []
    for exp in state.experiments:
        result = await toolkit.inject_fault(
            experiment=exp,
        )
        injections.append(result)

    step = _step(
        state.reasoning_chain,
        "inject_fault",
        (f"Injecting faults for {len(state.experiments)} experiments"),
        f"Injected {len(injections)} faults",
        start,
        "fault_injector",
    )

    return {
        "injections": injections,
        "total_faults_injected": len(injections),
        "stage": SCTStage.INJECT_FAULT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "inject_fault",
    }


# ------------------------------------------------------------------
# Node: observe_behavior
# ------------------------------------------------------------------


async def observe_behavior(
    state: SecurityChaosState,
) -> dict[str, Any]:
    """Observe system behavior during fault injection."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    observations = await toolkit.observe_behavior(
        injections=state.injections,
        experiments=state.experiments,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "injection_count": len(state.injections),
                "injections_sample": state.injections[:5],
                "experiments_sample": state.experiments[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_BEHAVIOR_ANALYSIS,
            user_prompt=(f"Analyze behavior:\n{ctx}"),
            schema=BehaviorAnalysisOutput,
        )
        if llm_out.detection_gaps:  # type: ignore[union-attr]
            observations.append(
                {
                    "observation_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "anomalies": llm_out.anomalies_detected,  # type: ignore[union-attr]
                    "detection_gaps": llm_out.detection_gaps,  # type: ignore[union-attr]
                    "recovery": llm_out.recovery_assessment,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="observe_behavior",
            gaps=len(llm_out.detection_gaps),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="observe_behavior",
        )

    step = _step(
        state.reasoning_chain,
        "observe_behavior",
        (f"Observing {len(state.injections)} injected faults"),
        f"Collected {len(observations)} observations",
        start,
        "monitor_connector",
    )

    return {
        "observations": observations,
        "stage": SCTStage.OBSERVE_BEHAVIOR,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "observe_behavior",
    }


# ------------------------------------------------------------------
# Node: assess_resilience
# ------------------------------------------------------------------


async def assess_resilience(
    state: SecurityChaosState,
) -> dict[str, Any]:
    """Assess resilience from observations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scores = await toolkit.assess_resilience(
        observations=state.observations,
        experiments=state.experiments,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "observations_sample": (state.observations[:5]),
                "experiment_count": state.total_experiments,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_RESILIENCE,
            user_prompt=(f"Assess resilience:\n{ctx}"),
            schema=ResilienceAssessmentOutput,
        )
        if isinstance(llm_out, ResilienceAssessmentOutput):
            scores.append(
                {
                    "component": "overall",
                    "score": llm_out.overall_score,
                    "critical_failures": llm_out.critical_failures,
                    "improvements": llm_out.improvements,
                    "rating": llm_out.rating,
                }
            )
        logger.info(
            "llm_enhanced",
            node="assess_resilience",
            score=llm_out.overall_score,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_resilience",
        )

    avg_score = 0.0
    critical = 0
    if scores:
        total = sum(s.get("score", 0.0) for s in scores)
        avg_score = total / len(scores)
        critical = sum(1 for s in scores if s.get("rating") == "critical")

    step = _step(
        state.reasoning_chain,
        "assess_resilience",
        (f"Assessing {len(state.observations)} observations"),
        (f"{len(scores)} scores, avg={avg_score:.1f}, {critical} critical"),
        start,
        "resilience_scorer",
    )

    return {
        "resilience_scores": scores,
        "avg_resilience_score": avg_score,
        "critical_failures": critical,
        "stage": SCTStage.ASSESS_RESILIENCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_resilience",
    }


# ------------------------------------------------------------------
# Node: document_findings
# ------------------------------------------------------------------


async def document_findings(
    state: SecurityChaosState,
) -> dict[str, Any]:
    """Document findings from the chaos campaign."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    findings = await toolkit.document_findings(
        experiments=state.experiments,
        observations=state.observations,
        scores=state.resilience_scores,
    )

    step = _step(
        state.reasoning_chain,
        "document_findings",
        (f"Documenting {state.total_experiments} experiments, {state.critical_failures} critical"),
        f"Produced {len(findings)} findings",
        start,
        "documentation",
    )

    return {
        "findings": findings,
        "stage": SCTStage.DOCUMENT_FINDINGS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "document_findings",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecurityChaosState,
) -> dict[str, Any]:
    """Generate the final chaos testing report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    report: dict[str, Any] = {
        "total_experiments": state.total_experiments,
        "total_faults": state.total_faults_injected,
        "avg_resilience": state.avg_resilience_score,
        "critical_failures": state.critical_failures,
        "findings_count": len(state.findings),
        "duration_ms": duration_ms,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "experiment_name": state.experiment_name,
                "total_experiments": state.total_experiments,
                "avg_resilience": state.avg_resilience_score,
                "critical_failures": state.critical_failures,
                "findings_sample": state.findings[:5],
                "scores_sample": state.resilience_scores[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate chaos report:\n{ctx}"),
            schema=ChaosReportOutput,
        )
        if isinstance(llm_out, ChaosReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "resilience_rating": llm_out.resilience_rating,
                    "recommendations": llm_out.recommendations,
                    "critical_gaps": llm_out.critical_gaps,
                    "next_experiments": llm_out.next_experiments,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recs=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    await toolkit.record_metric(
        metric_name="sct.run_completed",
        value=state.avg_resilience_score,
        tags={
            "experiments": str(state.total_experiments),
            "critical": str(state.critical_failures),
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_experiments} experiments"),
        (f"Report generated, resilience={state.avg_resilience_score:.1f}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": SCTStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
