"""Node implementations for the Security Simulation
Sandbox Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_simulation_sandbox.models import (
    ReasoningStep,
    SecuritySimulationSandboxState,
    SSSStage,
)
from shieldops.agents.security_simulation_sandbox.prompts import (
    SYSTEM_ANALYSIS,
    SYSTEM_REPORT,
    SYSTEM_SCENARIO,
    SandboxReportOutput,
    ScenarioConfigOutput,
    TestAnalysisOutput,
)
from shieldops.agents.security_simulation_sandbox.tools import (
    SecuritySimulationSandboxToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecuritySimulationSandboxToolkit | None = None


def _get_toolkit() -> SecuritySimulationSandboxToolkit:
    if _toolkit is None:
        return SecuritySimulationSandboxToolkit()
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
    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: provision_sandbox
# ------------------------------------------------------------------


async def provision_sandbox(
    state: SecuritySimulationSandboxState,
) -> dict[str, Any]:
    """Provision an isolated sandbox environment for
    security testing."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    instance = await toolkit.provision_sandbox(
        sandbox_type=state.sandbox_type.value,
        environment=state.target_environment,
        isolation_level=state.isolation_level,
    )

    step = _step(
        state.reasoning_chain,
        "provision_sandbox",
        (f"Type={state.sandbox_type}, env={state.target_environment}"),
        "Sandbox provisioned",
        start,
        "sandbox_provider",
    )

    return {
        "sandbox_instance": instance,
        "stage": SSSStage.PROVISION_SANDBOX,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "provision_sandbox",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: configure_scenario
# ------------------------------------------------------------------


async def configure_scenario(
    state: SecuritySimulationSandboxState,
) -> dict[str, Any]:
    """Configure attack scenarios within the provisioned
    sandbox."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sandbox_id = state.sandbox_instance.get("sandbox_id", "")
    configured = await toolkit.configure_scenario(
        scenarios=state.scenarios,
        sandbox_id=sandbox_id,
        sandbox_type=state.sandbox_type.value,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "sandbox_type": state.sandbox_type.value,
                "scenarios": state.scenarios[:5],
                "environment": state.target_environment,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_SCENARIO,
            user_prompt=(f"Configure test scenarios:\n{ctx}"),
            schema=ScenarioConfigOutput,
        )
        if llm_out.scenarios:  # type: ignore[union-attr]
            configured = [
                *configured,
                *llm_out.scenarios,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="configure_scenario",
            count=len(llm_out.scenarios),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="configure_scenario",
        )

    step = _step(
        state.reasoning_chain,
        "configure_scenario",
        f"Configuring {len(state.scenarios)} scenarios",
        f"Configured {len(configured)} scenarios",
        start,
        "scenario_engine",
    )

    return {
        "configured_scenarios": configured,
        "total_scenarios": len(configured),
        "stage": SSSStage.CONFIGURE_SCENARIO,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "configure_scenario",
    }


# ------------------------------------------------------------------
# Node: execute_test
# ------------------------------------------------------------------


async def execute_test(
    state: SecuritySimulationSandboxState,
) -> dict[str, Any]:
    """Execute configured test scenarios in the sandbox."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.execute_test(
        configured_scenarios=state.configured_scenarios,
        sandbox_instance=state.sandbox_instance,
    )

    passed = sum(1 for r in results if r.get("outcome") == "detected")
    failed = len(results) - passed

    step = _step(
        state.reasoning_chain,
        "execute_test",
        (f"Executing {len(state.configured_scenarios)} scenarios"),
        f"{passed} passed, {failed} failed",
        start,
        "test_executor",
    )

    return {
        "test_results": results,
        "tests_passed": passed,
        "tests_failed": failed,
        "stage": SSSStage.EXECUTE_TEST,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_test",
    }


# ------------------------------------------------------------------
# Node: collect_results
# ------------------------------------------------------------------


async def collect_results(
    state: SecuritySimulationSandboxState,
) -> dict[str, Any]:
    """Collect artifacts and evidence from test execution."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    artifacts = await toolkit.collect_results(
        test_results=state.test_results,
        sandbox_instance=state.sandbox_instance,
    )

    step = _step(
        state.reasoning_chain,
        "collect_results",
        (f"Collecting from {len(state.test_results)} tests"),
        f"Collected {len(artifacts)} artifacts",
        start,
        "artifact_collector",
    )

    return {
        "collected_artifacts": artifacts,
        "stage": SSSStage.COLLECT_RESULTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_results",
    }


# ------------------------------------------------------------------
# Node: analyze
# ------------------------------------------------------------------


async def analyze(
    state: SecuritySimulationSandboxState,
) -> dict[str, Any]:
    """Analyze test results for detection coverage and
    security gaps."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analysis = await toolkit.analyze_results(
        test_results=state.test_results,
        collected_artifacts=state.collected_artifacts,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "test_count": len(state.test_results),
                "results_sample": state.test_results[:5],
                "artifacts_count": len(state.collected_artifacts),
                "passed": state.tests_passed,
                "failed": state.tests_failed,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANALYSIS,
            user_prompt=f"Analyze test results:\n{ctx}",
            schema=TestAnalysisOutput,
        )
        if llm_out.detection_gaps:  # type: ignore[union-attr]
            rid = random.randint(1000, 9999)  # noqa: S311
            analysis.update(
                {
                    "analysis_id": f"llm-{rid}",
                    "detection_gaps": llm_out.detection_gaps,  # type: ignore[union-attr]
                    "evasion_techniques": llm_out.evasion_techniques,  # type: ignore[union-attr]
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze",
            gaps=len(llm_out.detection_gaps),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze",
        )

    # Compute detection coverage
    total = state.tests_passed + state.tests_failed
    coverage = state.tests_passed / total if total > 0 else 0.0

    step = _step(
        state.reasoning_chain,
        "analyze",
        (f"Analyzing {len(state.test_results)} results"),
        f"Coverage={coverage:.2f}",
        start,
        "analysis_engine",
    )

    return {
        "analysis": analysis,
        "detection_coverage": coverage,
        "stage": SSSStage.ANALYZE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecuritySimulationSandboxState,
) -> dict[str, Any]:
    """Generate the final sandbox testing report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # Track metric
    await toolkit.record_metric(
        metric_name="detection_coverage",
        value=state.detection_coverage,
        metadata={
            "sandbox_type": state.sandbox_type.value,
            "total_scenarios": state.total_scenarios,
        },
    )

    report: dict[str, Any] = {
        "sandbox_name": state.sandbox_name,
        "sandbox_type": state.sandbox_type.value,
        "total_scenarios": state.total_scenarios,
        "tests_passed": state.tests_passed,
        "tests_failed": state.tests_failed,
        "detection_coverage": state.detection_coverage,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "sandbox_name": state.sandbox_name,
                "sandbox_type": state.sandbox_type.value,
                "total_scenarios": state.total_scenarios,
                "tests_passed": state.tests_passed,
                "tests_failed": state.tests_failed,
                "detection_coverage": state.detection_coverage,
                "analysis": state.analysis,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate sandbox report:\n{ctx}",
            schema=SandboxReportOutput,
        )
        if isinstance(llm_out, SandboxReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "mitre_coverage": llm_out.mitre_coverage,
                    "risk_rating": llm_out.risk_rating,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recommendations=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_scenarios} scenarios"),
        (f"Report generated, coverage={state.detection_coverage:.2f}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": SSSStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
