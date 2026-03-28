"""Node implementations for Agent Fleet Optimizer."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.agent_fleet_optimizer.models import (
    AgentFleetOptimizerState,
    OptimizerStage,
)
from shieldops.agents.agent_fleet_optimizer.prompts import (
    SYSTEM_HEALTH_ANALYSIS,
    SYSTEM_ISSUE_DETECTION,
    SYSTEM_OPTIMIZATION_REPORT,
    HealthAnalysisOutput,
    IssueDetectionOutput,
    OptimizationReportOutput,
)
from shieldops.agents.agent_fleet_optimizer.tools import (
    AgentFleetOptimizerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AgentFleetOptimizerToolkit | None = None


def set_toolkit(
    toolkit: AgentFleetOptimizerToolkit,
) -> None:
    """Inject the toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> AgentFleetOptimizerToolkit:
    if _toolkit is None:
        return AgentFleetOptimizerToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# -------------------------------------------------------
# Node 1: collect_fleet_status
# -------------------------------------------------------
async def collect_fleet_status(
    state: AgentFleetOptimizerState,
) -> dict[str, Any]:
    """Collect current fleet status."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "fleet_optimizer.collect_fleet_status",
        tenant_id=state.tenant_id,
    )

    fleet = await toolkit.collect_fleet_status(state.tenant_id)

    chain_entry = (
        f"Fleet: {fleet.total_agents} agents, "
        f"{fleet.agents_running} running, "
        f"{fleet.agents_errored} errored"
    )

    return {
        "fleet_status": fleet,
        "stage": OptimizerStage.ANALYZE_HEALTH,
        "reasoning_chain": [chain_entry],
        "current_step": "collect_fleet_status",
        "session_start": start,
    }


# -------------------------------------------------------
# Node 2: analyze_health
# -------------------------------------------------------
async def analyze_health(
    state: AgentFleetOptimizerState,
) -> dict[str, Any]:
    """Analyze fleet health patterns."""
    toolkit = _get_toolkit()

    logger.info(
        "fleet_optimizer.analyze_health",
        total=state.fleet_status.total_agents,
    )

    health = await toolkit.analyze_health(state.fleet_status)

    # LLM enrichment
    lines = ["## Fleet Health"]
    for agent in state.fleet_status.agent_statuses:
        lines.append(f"- {agent['name']}: {agent['health']} cpu={agent['cpu_pct']}%")
    user_prompt = "\n".join(lines)

    try:
        result = cast(
            HealthAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_HEALTH_ANALYSIS,
                user_prompt=user_prompt,
                schema=HealthAnalysisOutput,
            ),
        )
        health.health_score = result.health_score
        health.patterns.extend(result.patterns[:5])
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="analyze_health",
            error=str(exc),
        )

    chain_entry = (
        f"Health: {health.health_score}% score, "
        f"{health.healthy_count} healthy, "
        f"{health.stuck_count} stuck"
    )

    return {
        "health_analysis": health,
        "agents_healthy": health.healthy_count,
        "agents_issues": (health.degraded_count + health.stuck_count + health.crashed_count),
        "stage": OptimizerStage.OPTIMIZE_SCHEDULES,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "analyze_health",
    }


# -------------------------------------------------------
# Node 3: optimize_schedules
# -------------------------------------------------------
async def optimize_schedules(
    state: AgentFleetOptimizerState,
) -> dict[str, Any]:
    """Optimize agent schedules."""
    toolkit = _get_toolkit()

    logger.info("fleet_optimizer.optimize_schedules")

    optimizations = await toolkit.optimize_schedules(state.fleet_status, state.health_analysis)

    chain_entry = f"Schedule optimizations: {len(optimizations)} recommended"

    return {
        "optimizations": optimizations,
        "stage": OptimizerStage.DETECT_ISSUES,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "optimize_schedules",
    }


# -------------------------------------------------------
# Node 4: detect_issues
# -------------------------------------------------------
async def detect_issues(
    state: AgentFleetOptimizerState,
) -> dict[str, Any]:
    """Detect fleet issues."""
    toolkit = _get_toolkit()

    logger.info("fleet_optimizer.detect_issues")

    issues = await toolkit.detect_issues(state.fleet_status, state.health_analysis)

    # LLM analysis
    lines = ["## Fleet Issues"]
    for iss in issues:
        lines.append(f"- {iss.agent_name}: {iss.issue_type} ({iss.severity}) — {iss.description}")
    user_prompt = "\n".join(lines)

    try:
        result = cast(
            IssueDetectionOutput,
            await llm_structured(
                system_prompt=SYSTEM_ISSUE_DETECTION,
                user_prompt=user_prompt,
                schema=IssueDetectionOutput,
            ),
        )
        root_note = "; ".join(result.root_causes[:3])
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="detect_issues",
            error=str(exc),
        )
        root_note = "Toolkit-based detection"

    chain_entry = f"Issues: {len(issues)} detected. {root_note[:100]}"

    return {
        "issues": issues,
        "stage": OptimizerStage.RECOMMEND_ACTIONS,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "detect_issues",
    }


# -------------------------------------------------------
# Node 5: recommend_actions
# -------------------------------------------------------
async def recommend_actions(
    state: AgentFleetOptimizerState,
) -> dict[str, Any]:
    """Generate action recommendations."""
    toolkit = _get_toolkit()

    logger.info("fleet_optimizer.recommend_actions")

    recs = await toolkit.recommend_actions(state.issues, state.optimizations)

    chain_entry = (
        f"Recommendations: {len(recs)} actions, "
        f"{sum(1 for r in recs if r.auto_executable)}"
        f" auto-executable"
    )

    utilization = round(state.fleet_status.avg_cpu_pct, 1)

    return {
        "recommendations": recs,
        "utilization_pct": utilization,
        "stage": OptimizerStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "recommend_actions",
    }


# -------------------------------------------------------
# Node 6: report
# -------------------------------------------------------
async def report(
    state: AgentFleetOptimizerState,
) -> dict[str, Any]:
    """Generate fleet optimization report."""
    logger.info(
        "fleet_optimizer.report",
        healthy=state.agents_healthy,
        issues=state.agents_issues,
    )

    lines = [
        "## Fleet Optimization Report",
        f"- Total agents: {state.fleet_status.total_agents}",
        f"- Healthy: {state.agents_healthy}",
        f"- Issues: {state.agents_issues}",
        f"- Utilization: {state.utilization_pct}%",
        f"- Recommendations: {len(state.recommendations)}",
    ]
    for entry in state.reasoning_chain:
        lines.append(f"- {entry}")
    user_prompt = "\n".join(lines)

    try:
        result = cast(
            OptimizationReportOutput,
            await llm_structured(
                system_prompt=(SYSTEM_OPTIMIZATION_REPORT),
                user_prompt=user_prompt,
                schema=OptimizationReportOutput,
            ),
        )
        summary = result.executive_summary
        recs = result.top_recommendations
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="report",
            error=str(exc),
        )
        summary = (
            f"Fleet: {state.agents_healthy} healthy, "
            f"{state.agents_issues} issues, "
            f"{len(state.recommendations)} actions"
        )
        recs = [r.reason for r in state.recommendations[:5]]

    duration = 0
    if state.session_start:
        duration = _elapsed_ms(state.session_start)

    stats = {
        "total_agents": (state.fleet_status.total_agents),
        "agents_healthy": state.agents_healthy,
        "agents_issues": state.agents_issues,
        "utilization_pct": state.utilization_pct,
        "health_score": (state.health_analysis.health_score),
        "recommendations": len(state.recommendations),
        "summary": summary[:500],
        "top_recs": recs[:5],
    }

    chain_entry = f"Report: {state.agents_healthy} healthy, {state.agents_issues} issues"

    return {
        "stats": stats,
        "stage": OptimizerStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "complete",
        "session_duration_ms": duration,
    }
