"""Node implementations for the Digital Twin Security Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.digital_twin_security.models import (
    DigitalTwinSecurityState,
    ReasoningStep,
)
from shieldops.agents.digital_twin_security.prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_REPORT,
    PostureReportOutput,
    SimulationAnalysisOutput,
)
from shieldops.agents.digital_twin_security.tools import DigitalTwinSecurityToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: DigitalTwinSecurityToolkit | None = None


def set_toolkit(toolkit: DigitalTwinSecurityToolkit) -> None:
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> DigitalTwinSecurityToolkit:
    if _toolkit is None:
        return DigitalTwinSecurityToolkit()
    return _toolkit


async def create_twin(state: DigitalTwinSecurityState) -> dict[str, Any]:
    """Create a digital twin from the provided configuration."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    twin = await toolkit.create_twin(state.twin_config)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="create_twin",
        input_summary=f"Creating {state.twin_config.get('twin_type', 'infrastructure')} twin",
        output_summary=f"Twin created: {twin.get('twin_id', 'unknown')}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="cloud_connector",
    )

    return {
        "digital_twin": twin,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "create_twin",
        "session_start": start,
    }


async def configure_environment(state: DigitalTwinSecurityState) -> dict[str, Any]:
    """Configure the simulation environment for the digital twin."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    overrides = state.twin_config.get("environment_overrides", {})
    env_config = await toolkit.configure_environment(state.digital_twin, overrides)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="configure_environment",
        input_summary=f"Configuring environment for twin {state.digital_twin.get('twin_id', '')}",
        output_summary=f"Environment configured: isolation={env_config.get('isolation_mode')}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="environment_manager",
    )

    return {
        "environment_config": env_config,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "configure_environment",
    }


async def execute_simulations(state: DigitalTwinSecurityState) -> dict[str, Any]:
    """Build and execute all attack simulation scenarios against the twin."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scenarios = await toolkit.build_scenarios(state.scenarios_requested, state.digital_twin)

    results: list[dict[str, Any]] = []
    for scenario in scenarios:
        result = await toolkit.simulate(scenario, state.digital_twin, state.environment_config)
        results.append(result)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_simulations",
        input_summary=f"Executing {len(scenarios)} attack scenarios",
        output_summary=(
            f"Completed {len(results)} simulations, "
            f"{sum(1 for r in results if r.get('success'))} attacks succeeded"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="simulation_engine",
    )

    return {
        "scenarios": scenarios,
        "simulation_results": results,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_simulations",
    }


async def analyze_results(state: DigitalTwinSecurityState) -> dict[str, Any]:
    """Analyze simulation results to identify security gaps and patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analysis = await toolkit.analyze_results(state.simulation_results)

    # LLM enhancement: deeper analysis reasoning
    try:
        analysis_context = _json.dumps(
            {
                "total_scenarios": analysis.get("total_scenarios"),
                "scenarios_succeeded": analysis.get("scenarios_succeeded"),
                "block_rate": analysis.get("block_rate"),
                "controls_bypassed": analysis.get("unique_controls_bypassed", []),
                "critical_findings": analysis.get("critical_findings", [])[:10],
                "average_risk_score": analysis.get("average_risk_score"),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=f"Simulation results context:\n{analysis_context}",
            schema=SimulationAnalysisOutput,
        )
        if hasattr(llm_result, "summary"):
            analysis["llm_summary"] = llm_result.summary
            analysis["llm_remediation_priorities"] = llm_result.remediation_priorities
        logger.info(
            "llm_enhanced",
            node="analyze_results",
            controls_effectiveness=getattr(llm_result, "controls_effectiveness", 0.0),
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="analyze_results")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_results",
        input_summary=f"Analyzing {len(state.simulation_results)} simulation results",
        output_summary=(
            f"Analysis complete: block_rate={analysis.get('block_rate', 0):.2f}, "
            f"critical_findings={len(analysis.get('critical_findings', []))}"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    return {
        "analysis": analysis,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_results",
    }


async def validate_posture(state: DigitalTwinSecurityState) -> dict[str, Any]:
    """Validate overall security posture based on analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    posture = await toolkit.validate_posture(state.analysis)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="validate_posture",
        input_summary=(
            f"Validating posture from {state.analysis.get('total_scenarios', 0)} scenarios"
        ),
        output_summary=(
            f"Verdict={posture.get('verdict')}, "
            f"risk_score={posture.get('overall_risk_score', 0):.1f}, "
            f"confidence={posture.get('confidence', 0):.2f}"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="posture_validator",
    )

    return {
        "posture_assessment": posture,
        "verdict": posture.get("verdict", ""),
        "overall_risk_score": posture.get("overall_risk_score", 0.0),
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_posture",
    }


async def generate_report(state: DigitalTwinSecurityState) -> dict[str, Any]:
    """Generate the final posture assessment report."""
    start = datetime.now(UTC)

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report: dict[str, Any] = {
        "tenant_id": state.tenant_id,
        "twin": state.digital_twin,
        "posture_assessment": state.posture_assessment,
        "verdict": state.verdict,
        "overall_risk_score": state.overall_risk_score,
        "scenarios_executed": len(state.scenarios),
        "simulation_results": state.simulation_results,
        "analysis_summary": state.analysis.get("llm_summary", ""),
        "remediation_priorities": state.posture_assessment.get("remediation_priorities", []),
        "duration_ms": duration_ms,
    }

    # LLM enhancement: executive report
    try:
        report_context = _json.dumps(
            {
                "verdict": state.verdict,
                "overall_risk_score": state.overall_risk_score,
                "total_scenarios": len(state.scenarios),
                "scenarios_succeeded": state.posture_assessment.get("scenarios_succeeded", 0),
                "scenarios_blocked": state.posture_assessment.get("scenarios_blocked", 0),
                "critical_findings": state.posture_assessment.get("critical_findings", [])[:5],
                "remediation_priorities": state.posture_assessment.get(
                    "remediation_priorities", []
                )[:5],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Posture assessment context:\n{report_context}",
            schema=PostureReportOutput,
        )
        if hasattr(llm_result, "executive_summary"):
            report["executive_summary"] = llm_result.executive_summary
            report["top_findings"] = llm_result.top_findings
            report["recommended_actions"] = llm_result.recommended_actions
        logger.info(
            "llm_enhanced",
            node="generate_report",
            llm_verdict=getattr(llm_result, "verdict", "unknown"),
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="generate_report")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=f"Generating report for verdict={state.verdict}",
        output_summary=(
            f"Report generated: {len(state.scenarios)} scenarios, "
            f"risk_score={state.overall_risk_score:.1f}, duration={duration_ms}ms"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
