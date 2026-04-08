"""Node implementations for the Threat Simulation
Engine Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.threat_simulation_engine.models import (
    ReasoningStep,
    ThreatSimulationEngineState,
    TSEStage,
)
from shieldops.agents.threat_simulation_engine.prompts import (
    SYSTEM_DETECTION_ANALYSIS,
    SYSTEM_GAP_ANALYSIS,
    SYSTEM_PLAN_SCENARIO,
    SYSTEM_REPORT,
    DetectionAnalysisOutput,
    GapAnalysisOutput,
    ScenarioPlanOutput,
    SimulationReportOutput,
)
from shieldops.agents.threat_simulation_engine.tools import (
    ThreatSimulationEngineToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ThreatSimulationEngineToolkit | None = None


def _get_toolkit() -> ThreatSimulationEngineToolkit:
    if _toolkit is None:
        return ThreatSimulationEngineToolkit()
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
# Node: plan_scenario
# ------------------------------------------------------------------


async def plan_scenario(
    state: ThreatSimulationEngineState,
) -> dict[str, Any]:
    """Plan adversary simulation scenarios from target
    MITRE ATT&CK techniques."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.plan_scenario(
        techniques=state.target_techniques,
        scope=state.scope,
        simulation_type=state.simulation_type.value,
    )

    scenarios: list[dict[str, Any]] = list(results)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "campaign": state.campaign_name,
                "techniques": state.target_techniques,
                "scope": state.scope,
                "simulation_type": state.simulation_type.value,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_PLAN_SCENARIO,
            user_prompt=(f"Plan attack scenarios for:\n{ctx}"),
            schema=ScenarioPlanOutput,
        )
        if llm_out.scenarios:  # type: ignore[union-attr]
            scenarios = [
                *scenarios,
                *llm_out.scenarios,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="plan_scenario",
            count=len(llm_out.scenarios),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="plan_scenario",
        )

    step = _step(
        state.reasoning_chain,
        "plan_scenario",
        (f"Techniques: {len(state.target_techniques)}, type={state.simulation_type}"),
        f"Planned {len(scenarios)} scenarios",
        start,
        "mitre_mapper",
    )

    return {
        "scenarios": scenarios,
        "stage": TSEStage.PLAN_SCENARIO,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "plan_scenario",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: deploy_attack
# ------------------------------------------------------------------


async def deploy_attack(
    state: ThreatSimulationEngineState,
) -> dict[str, Any]:
    """Deploy simulated attacks from planned scenarios."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    all_attacks: list[dict[str, Any]] = []
    for scenario in state.scenarios:
        attacks = await toolkit.deploy_attack(
            scenario=scenario,
            scope=state.scope,
        )
        all_attacks.extend(attacks)

    step = _step(
        state.reasoning_chain,
        "deploy_attack",
        (f"Deploying {len(state.scenarios)} scenarios"),
        f"Deployed {len(all_attacks)} attacks",
        start,
        "bas_platform",
    )

    return {
        "attacks": all_attacks,
        "total_attacks": len(all_attacks),
        "stage": TSEStage.DEPLOY_ATTACK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "deploy_attack",
    }


# ------------------------------------------------------------------
# Node: monitor_detection
# ------------------------------------------------------------------


async def monitor_detection(
    state: ThreatSimulationEngineState,
) -> dict[str, Any]:
    """Monitor detection pipeline for alerts triggered
    by deployed attacks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    detections = await toolkit.monitor_detection(
        attacks=state.attacks,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "attack_count": len(state.attacks),
                "attacks_sample": state.attacks[:5],
                "detections": detections[:10],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DETECTION_ANALYSIS,
            user_prompt=(f"Analyze detection results:\n{ctx}"),
            schema=DetectionAnalysisOutput,
        )
        if llm_out.detection_sources:  # type: ignore[union-attr]
            detections.append(
                {
                    "detection_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "detected_count": llm_out.detected_count,  # type: ignore[union-attr]
                    "missed_count": llm_out.missed_count,  # type: ignore[union-attr]
                    "avg_detection_time_ms": llm_out.avg_detection_time_ms,  # type: ignore[union-attr]
                    "sources": llm_out.detection_sources,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="monitor_detection",
            detected=llm_out.detected_count,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="monitor_detection",
        )

    detected = sum(1 for d in detections if d.get("detected"))

    step = _step(
        state.reasoning_chain,
        "monitor_detection",
        (f"Monitoring {len(state.attacks)} attacks"),
        f"Detected {detected} of {len(state.attacks)}",
        start,
        "detection_pipeline",
    )

    return {
        "detections": detections,
        "detected_count": detected,
        "stage": TSEStage.MONITOR_DETECTION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "monitor_detection",
    }


# ------------------------------------------------------------------
# Node: evaluate_response
# ------------------------------------------------------------------


async def evaluate_response(
    state: ThreatSimulationEngineState,
) -> dict[str, Any]:
    """Evaluate blue team response effectiveness."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    evaluations = await toolkit.evaluate_response(
        detections=state.detections,
        attacks=state.attacks,
    )

    step = _step(
        state.reasoning_chain,
        "evaluate_response",
        (f"Evaluating {len(state.detections)} detections"),
        f"Produced {len(evaluations)} evaluations",
        start,
        "response_evaluator",
    )

    return {
        "evaluations": evaluations,
        "stage": TSEStage.EVALUATE_RESPONSE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "evaluate_response",
    }


# ------------------------------------------------------------------
# Node: generate_gaps
# ------------------------------------------------------------------


async def generate_gaps(
    state: ThreatSimulationEngineState,
) -> dict[str, Any]:
    """Identify detection coverage gaps from simulation
    results."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    gaps = await toolkit.generate_gap_analysis(
        attacks=state.attacks,
        detections=state.detections,
        evaluations=state.evaluations,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "total_attacks": state.total_attacks,
                "detected_count": state.detected_count,
                "attacks_sample": state.attacks[:5],
                "detections_sample": state.detections[:5],
                "evaluations_sample": state.evaluations[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_GAP_ANALYSIS,
            user_prompt=f"Analyze detection gaps:\n{ctx}",
            schema=GapAnalysisOutput,
        )
        if llm_out.gaps:  # type: ignore[union-attr]
            gaps = [
                *gaps,
                *llm_out.gaps,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="generate_gaps",
            gap_count=len(llm_out.gaps),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_gaps",
        )

    step = _step(
        state.reasoning_chain,
        "generate_gaps",
        (f"Analyzing {state.total_attacks} attacks, {state.detected_count} detected"),
        f"Found {len(gaps)} detection gaps",
        start,
        "gap_analyzer",
    )

    return {
        "gaps": gaps,
        "gap_count": len(gaps),
        "stage": TSEStage.GENERATE_GAPS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_gaps",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: ThreatSimulationEngineState,
) -> dict[str, Any]:
    """Generate the final simulation campaign report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    detection_rate = state.detected_count / state.total_attacks if state.total_attacks > 0 else 0.0
    overall_score = min(1.0, 0.4 + detection_rate * 0.6) if state.detected_count > 0 else 0.1

    report: dict[str, Any] = {
        "campaign": state.campaign_name,
        "total_attacks": state.total_attacks,
        "detected": state.detected_count,
        "gaps": state.gap_count,
        "detection_rate": detection_rate,
        "overall_score": overall_score,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "campaign": state.campaign_name,
                "simulation_type": state.simulation_type.value,
                "total_attacks": state.total_attacks,
                "detected_count": state.detected_count,
                "gap_count": state.gap_count,
                "scenarios_sample": state.scenarios[:5],
                "gaps_sample": state.gaps[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate simulation report:\n{ctx}"),
            schema=SimulationReportOutput,
        )
        if isinstance(llm_out, SimulationReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "critical_findings": llm_out.critical_findings,
                    "recommendations": llm_out.recommendations,
                    "overall_rating": llm_out.overall_rating,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                findings=len(llm_out.critical_findings),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record metrics
    await toolkit.record_metric(
        campaign_id=state.request_id,
        outcome={
            "total_attacks": state.total_attacks,
            "detected": state.detected_count,
            "gaps": state.gap_count,
            "detection_rate": detection_rate,
            "overall_score": overall_score,
        },
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_attacks} attacks"),
        (f"Report generated, detection_rate={detection_rate:.2f}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "detection_rate": detection_rate,
        "overall_score": overall_score,
        "session_duration_ms": duration_ms,
        "stage": TSEStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
