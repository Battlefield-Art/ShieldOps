"""Node implementations for Threat Scenario Runner."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.threat_scenario_runner.models import (
    ScenarioCategory,
    ScenarioStage,
    ThreatScenarioRunnerState,
    Verdict,
)
from shieldops.agents.threat_scenario_runner.prompts import (
    SYSTEM_CONTROL_EVAL,
    SYSTEM_SCENARIO_LOAD,
    SYSTEM_VERDICT,
    ControlEvalOutput,
    ScenarioLoadOutput,
    VerdictOutput,
)
from shieldops.agents.threat_scenario_runner.tools import (
    ThreatScenarioRunnerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ThreatScenarioRunnerToolkit | None = None


def set_toolkit(
    toolkit: ThreatScenarioRunnerToolkit,
) -> None:
    """Inject the toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ThreatScenarioRunnerToolkit:
    if _toolkit is None:
        return ThreatScenarioRunnerToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# -------------------------------------------------------
# Node 1: load_scenario
# -------------------------------------------------------
async def load_scenario(
    state: ThreatScenarioRunnerState,
) -> dict[str, Any]:
    """Load and enrich the threat scenario."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "scenario_runner.load_scenario",
        tenant_id=state.tenant_id,
    )

    category = state.scenario.category or ScenarioCategory.RANSOMWARE_READINESS
    scenario = await toolkit.load_scenario(category, state.scenario.description)

    # LLM enrichment
    user_prompt = (
        f"Category: {category.value}\n"
        f"Description: {scenario.description}\n"
        f"Steps: {', '.join(scenario.steps)}"
    )
    try:
        result = cast(
            ScenarioLoadOutput,
            await llm_structured(
                system_prompt=SYSTEM_SCENARIO_LOAD,
                user_prompt=user_prompt,
                schema=ScenarioLoadOutput,
            ),
        )
        scenario.steps = result.steps[:12]
        scenario.expected_controls = result.expected_controls[:10]
        scenario.mitre_techniques = result.mitre_techniques[:8]
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="load_scenario",
            error=str(exc),
        )

    chain_entry = f"Loaded scenario '{scenario.name}' with {len(scenario.steps)} steps"

    return {
        "scenario": scenario,
        "stage": ScenarioStage.SETUP_ENVIRONMENT,
        "reasoning_chain": [chain_entry],
        "current_step": "load_scenario",
        "session_start": start,
    }


# -------------------------------------------------------
# Node 2: setup_environment
# -------------------------------------------------------
async def setup_environment(
    state: ThreatScenarioRunnerState,
) -> dict[str, Any]:
    """Set up isolated test environment."""
    toolkit = _get_toolkit()

    logger.info(
        "scenario_runner.setup_environment",
        scenario_id=state.scenario.id,
    )

    setup = await toolkit.setup_environment(state.scenario)

    chain_entry = (
        f"Environment: {setup.environment}, "
        f"isolated={setup.isolation_verified}, "
        f"rollback={setup.rollback_ready}"
    )

    return {
        "setup": setup,
        "stage": ScenarioStage.EXECUTE_STEPS,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "setup_environment",
    }


# -------------------------------------------------------
# Node 3: execute_steps
# -------------------------------------------------------
async def execute_steps(
    state: ThreatScenarioRunnerState,
) -> dict[str, Any]:
    """Execute scenario steps safely."""
    toolkit = _get_toolkit()

    logger.info(
        "scenario_runner.execute_steps",
        scenario_id=state.scenario.id,
    )

    steps = await toolkit.execute_steps(state.scenario)
    passed = sum(1 for s in steps if s.passed)

    chain_entry = f"Executed {len(steps)} steps: {passed} passed, {len(steps) - passed} failed"

    return {
        "steps_executed": steps,
        "stage": ScenarioStage.EVALUATE_CONTROLS,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "execute_steps",
    }


# -------------------------------------------------------
# Node 4: evaluate_controls
# -------------------------------------------------------
async def evaluate_controls(
    state: ThreatScenarioRunnerState,
) -> dict[str, Any]:
    """Evaluate security controls."""
    toolkit = _get_toolkit()

    logger.info(
        "scenario_runner.evaluate_controls",
        scenario_id=state.scenario.id,
    )

    evals = await toolkit.evaluate_controls(state.scenario, state.steps_executed)

    # LLM analysis
    lines = ["## Control Evaluation Results"]
    for e in evals:
        lines.append(f"- {e.control_name}: effective={e.effective} confidence={e.confidence}")
    user_prompt = "\n".join(lines)

    try:
        result = cast(
            ControlEvalOutput,
            await llm_structured(
                system_prompt=SYSTEM_CONTROL_EVAL,
                user_prompt=user_prompt,
                schema=ControlEvalOutput,
            ),
        )
        gap_note = result.gap_analysis[:120]
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="evaluate_controls",
            error=str(exc),
        )
        gap_note = "Toolkit-based evaluation"

    passed = sum(1 for e in evals if e.effective)
    failed = len(evals) - passed

    chain_entry = f"Controls: {passed} effective, {failed} failed. {gap_note}"

    return {
        "evaluations": evals,
        "controls_passed": passed,
        "controls_failed": failed,
        "stage": ScenarioStage.GENERATE_VERDICT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "evaluate_controls",
    }


# -------------------------------------------------------
# Node 5: generate_verdict
# -------------------------------------------------------
async def generate_verdict(
    state: ThreatScenarioRunnerState,
) -> dict[str, Any]:
    """Generate pass/fail verdict."""
    toolkit = _get_toolkit()

    logger.info(
        "scenario_runner.generate_verdict",
        passed=state.controls_passed,
        failed=state.controls_failed,
    )

    verdict = await toolkit.generate_verdict(state.scenario, state.evaluations)

    # LLM enrichment
    lines = [
        f"Scenario: {state.scenario.name}",
        f"Controls passed: {state.controls_passed}",
        f"Controls failed: {state.controls_failed}",
        f"Score: {verdict.score}%",
    ]
    user_prompt = "\n".join(lines)

    try:
        result = cast(
            VerdictOutput,
            await llm_structured(
                system_prompt=SYSTEM_VERDICT,
                user_prompt=user_prompt,
                schema=VerdictOutput,
            ),
        )
        if result.verdict in [v.value for v in Verdict]:
            verdict.verdict = Verdict(result.verdict)
        verdict.summary = result.executive_summary[:300]
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="generate_verdict",
            error=str(exc),
        )

    chain_entry = f"Verdict: {verdict.verdict.value} ({verdict.score}%)"

    return {
        "verdict": verdict,
        "stage": ScenarioStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "generate_verdict",
    }


# -------------------------------------------------------
# Node 6: report
# -------------------------------------------------------
async def report(
    state: ThreatScenarioRunnerState,
) -> dict[str, Any]:
    """Generate final scenario report."""
    logger.info(
        "scenario_runner.report",
        verdict=state.verdict.verdict,
        score=state.verdict.score,
    )

    duration = 0
    if state.session_start:
        duration = _elapsed_ms(state.session_start)

    stats = {
        "scenario_name": state.scenario.name,
        "category": state.scenario.category,
        "verdict": state.verdict.verdict,
        "score": state.verdict.score,
        "controls_passed": state.controls_passed,
        "controls_failed": state.controls_failed,
        "steps_executed": len(state.steps_executed),
        "summary": state.verdict.summary[:500],
        "remediation": (state.verdict.remediation_items[:5]),
    }

    chain_entry = f"Report: {state.verdict.verdict.value} ({state.verdict.score}%)"

    return {
        "stats": stats,
        "stage": ScenarioStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "complete",
        "session_duration_ms": duration,
    }
