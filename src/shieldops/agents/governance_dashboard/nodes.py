"""Node implementations for the Governance Dashboard Agent."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.governance_dashboard.models import (
    GovernanceStage,
)
from shieldops.agents.governance_dashboard.prompts import (
    SYSTEM_ASSESS_POLICIES,
    SYSTEM_EXECUTIVE_SUMMARY,
    SYSTEM_GENERATE_INSIGHTS,
    SYSTEM_SCORE_RISK,
    ExecutiveSummaryOutput,
    InsightGenerationOutput,
    PolicyInsightOutput,
    RiskScoringOutput,
)
from shieldops.agents.governance_dashboard.tools import (
    GovernanceDashboardToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: GovernanceDashboardToolkit | None = None


def set_toolkit(
    toolkit: GovernanceDashboardToolkit,
) -> None:
    """Set the global toolkit instance."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> GovernanceDashboardToolkit:
    if _toolkit is None:
        return GovernanceDashboardToolkit()
    return _toolkit


async def collect_metrics(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Collect governance metrics across all policy domains."""
    start = time.time()
    toolkit = _get_toolkit()

    tenant_id = state.get("tenant_id", "")

    metrics = await toolkit.collect_metrics(
        tenant_id=tenant_id,
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])

    return {
        "metrics": metrics,
        "stage": GovernanceStage.COLLECT_METRICS,
        "current_step": "collect_metrics",
        "session_start": start,
        "reasoning_chain": [
            *chain,
            (
                f"[collect_metrics] Collected {len(metrics)} "
                f"metrics for tenant {tenant_id} "
                f"({elapsed}ms)"
            ),
        ],
    }


async def assess_policies(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Assess policy adherence across domains."""
    start = time.time()
    toolkit = _get_toolkit()

    metrics = state.get("metrics", [])

    assessments = await toolkit.assess_policies(
        metrics=metrics,
    )

    # LLM enhancement for policy insights
    try:
        result = await llm_structured(
            system_prompt=SYSTEM_ASSESS_POLICIES,
            user_prompt=(
                f"Domains assessed: {len(assessments)}\n"
                f"Metrics collected: {len(metrics)}\n"
                f"Gaps found: {sum(len(a.gaps) for a in assessments)}"
            ),
            output_schema=PolicyInsightOutput,
        )
        _ = result.critical_gaps
    except Exception:
        logger.warning(
            "governance_dashboard.llm_assess_fallback",
        )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])

    return {
        "policy_assessments": assessments,
        "stage": GovernanceStage.ASSESS_POLICIES,
        "current_step": "assess_policies",
        "reasoning_chain": [
            *chain,
            (f"[assess_policies] Assessed {len(assessments)} domains ({elapsed}ms)"),
        ],
    }


async def score_risk(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Score risk posture per domain and overall."""
    start = time.time()
    toolkit = _get_toolkit()

    assessments = state.get("policy_assessments", [])
    metrics = state.get("metrics", [])

    risk_scores = await toolkit.score_risk(
        assessments=assessments,
        metrics=metrics,
    )

    overall_posture = await toolkit.compute_overall_posture(
        risk_scores=risk_scores,
    )

    # LLM enhancement for risk insights
    try:
        result = await llm_structured(
            system_prompt=SYSTEM_SCORE_RISK,
            user_prompt=(
                f"Domains: {len(risk_scores)}\n"
                f"Overall posture: {overall_posture.value}\n"
                f"Scores: {[s.score for s in risk_scores]}"
            ),
            output_schema=RiskScoringOutput,
        )
        _ = result.top_risks
    except Exception:
        logger.warning(
            "governance_dashboard.llm_risk_fallback",
        )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])

    return {
        "risk_scores": risk_scores,
        "overall_posture": overall_posture,
        "stage": GovernanceStage.SCORE_RISK,
        "current_step": "score_risk",
        "reasoning_chain": [
            *chain,
            (
                f"[score_risk] Scored {len(risk_scores)} "
                f"domains, overall={overall_posture.value} "
                f"({elapsed}ms)"
            ),
        ],
    }


async def generate_insights(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate actionable governance insights."""
    start = time.time()

    metrics = state.get("metrics", [])
    assessments = state.get("policy_assessments", [])
    risk_scores = state.get("risk_scores", [])

    # Default insights from data
    insights: list[str] = []
    for assessment in assessments:
        if assessment.adherence_pct < 75.0:
            insights.append(
                f"{assessment.domain.value}: adherence at "
                f"{assessment.adherence_pct}% — below threshold"
            )
        if assessment.gaps:
            insights.append(f"{assessment.domain.value}: {len(assessment.gaps)} control gaps")

    # LLM enhancement for deeper insights
    try:
        result = await llm_structured(
            system_prompt=SYSTEM_GENERATE_INSIGHTS,
            user_prompt=(
                f"Metrics: {len(metrics)}\n"
                f"Assessments: {len(assessments)}\n"
                f"Risk scores: {len(risk_scores)}\n"
                f"Current insights: {len(insights)}"
            ),
            output_schema=InsightGenerationOutput,
        )
        insights.extend(result.insights)
    except Exception:
        logger.warning(
            "governance_dashboard.llm_insights_fallback",
        )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])

    return {
        "insights": insights,
        "stage": GovernanceStage.GENERATE_INSIGHTS,
        "current_step": "generate_insights",
        "reasoning_chain": [
            *chain,
            (f"[generate_insights] Generated {len(insights)} insights ({elapsed}ms)"),
        ],
    }


async def executive_summary(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate executive summary."""
    start = time.time()
    toolkit = _get_toolkit()

    metrics = state.get("metrics", [])
    assessments = state.get("policy_assessments", [])
    risk_scores = state.get("risk_scores", [])
    overall_posture = state.get("overall_posture", "adequate")
    insights = state.get("insights", [])

    summary = await toolkit.build_executive_summary(
        metrics=metrics,
        assessments=assessments,
        risk_scores=risk_scores,
        overall_posture=overall_posture,
        insights=insights,
    )

    # LLM enhancement for polished summary
    try:
        result = await llm_structured(
            system_prompt=SYSTEM_EXECUTIVE_SUMMARY,
            user_prompt=(
                f"Posture: {overall_posture}\n"
                f"Domains: {len(assessments)}\n"
                f"Insights: {len(insights)}\n"
                f"Draft: {summary}"
            ),
            output_schema=ExecutiveSummaryOutput,
        )
        summary = result.summary
    except Exception:
        logger.warning(
            "governance_dashboard.llm_summary_fallback",
        )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])

    return {
        "executive_summary": summary,
        "stage": GovernanceStage.EXECUTIVE_SUMMARY,
        "current_step": "executive_summary",
        "reasoning_chain": [
            *chain,
            (f"[executive_summary] Built executive summary ({elapsed}ms)"),
        ],
    }


async def report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate the final governance report."""
    start = time.time()

    metrics = state.get("metrics", [])
    assessments = state.get("policy_assessments", [])
    risk_scores = state.get("risk_scores", [])
    insights = state.get("insights", [])
    overall_posture = state.get("overall_posture", "adequate")
    exec_summary = state.get("executive_summary", "")

    stats: dict[str, Any] = {
        "metrics_collected": len(metrics),
        "domains_assessed": len(assessments),
        "risk_scores": len(risk_scores),
        "insights_generated": len(insights),
        "overall_posture": (
            overall_posture.value if hasattr(overall_posture, "value") else str(overall_posture)
        ),
        "executive_summary": exec_summary,
    }

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])

    total_ms = elapsed
    session_start = state.get("session_start", 0.0)
    if session_start:
        total_ms = int((time.time() - session_start) * 1000)

    return {
        "stats": stats,
        "stage": GovernanceStage.REPORT,
        "current_step": "report",
        "session_duration_ms": total_ms,
        "reasoning_chain": [
            *chain,
            (f"[report] Generated final report ({elapsed}ms)"),
        ],
    }
