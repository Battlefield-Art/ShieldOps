"""Security Scorecard Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    DomainScore,
    ScorecardStage,
    SecurityInsight,
    TrendData,
)
from .prompts import (
    SYSTEM_ANALYZE_TRENDS,
    SYSTEM_GENERATE_INSIGHTS,
    SYSTEM_REPORT,
    InsightGenerationOutput,
    ScorecardReportOutput,
    TrendAnalysisOutput,
)
from .tools import SecurityScorecardToolkit

logger = structlog.get_logger()


async def collect_domain_scores(
    state: dict[str, Any],
    toolkit: SecurityScorecardToolkit,
) -> dict[str, Any]:
    """Collect scores from all security domains."""
    logger.info("scorecard.node.collect_domain_scores")

    tenant_id = state.get("tenant_id", "")
    scores = await toolkit.collect_domain_scores(
        tenant_id,
    )
    data = [s.model_dump() for s in scores]

    return {
        "current_stage": (ScorecardStage.COLLECT_DOMAIN_SCORES.value),
        "domain_scores": data,
        "reasoning_chain": (
            state.get("reasoning_chain", [])
            + [f"Collected scores for {len(scores)} security domains"]
        ),
    }


async def calculate_composite(
    state: dict[str, Any],
    toolkit: SecurityScorecardToolkit,
) -> dict[str, Any]:
    """Calculate weighted composite score."""
    logger.info("scorecard.node.calculate_composite")

    raw = state.get("domain_scores", [])
    scores = [DomainScore(**s) for s in raw]
    composite = await toolkit.calculate_composite(
        scores,
    )
    data = composite.model_dump()

    return {
        "current_stage": (ScorecardStage.CALCULATE_COMPOSITE.value),
        "composite_score": data,
        "overall_grade": composite.grade.value,
        "reasoning_chain": (
            state.get("reasoning_chain", [])
            + [f"Composite score: {composite.total_score} ({composite.grade.value})"]
        ),
    }


async def track_trends(
    state: dict[str, Any],
    toolkit: SecurityScorecardToolkit,
) -> dict[str, Any]:
    """Track 30/60/90 day score trends."""
    logger.info("scorecard.node.track_trends")

    composite = state.get("composite_score", {})
    score = composite.get("total_score", 0.0)
    trends = await toolkit.track_trends(score)

    # LLM trend analysis
    try:
        context = json.dumps(
            [t.model_dump() for t in trends],
            default=str,
        )
        result = await llm_structured(
            system_prompt=SYSTEM_ANALYZE_TRENDS,
            user_prompt=(f"Current score: {score}\nTrends:\n{context}"),
            output_schema=TrendAnalysisOutput,
        )
        reasoning = result.trend_summary
    except Exception:
        logger.debug("scorecard.llm_trends_fallback")
        reasoning = f"Tracked {len(trends)} trend periods"

    data = [t.model_dump() for t in trends]

    return {
        "current_stage": (ScorecardStage.TRACK_TRENDS.value),
        "trends": data,
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def compare_benchmarks(
    state: dict[str, Any],
    toolkit: SecurityScorecardToolkit,
) -> dict[str, Any]:
    """Compare against industry benchmarks."""
    logger.info("scorecard.node.compare_benchmarks")

    composite = state.get("composite_score", {})
    score = composite.get("total_score", 0.0)
    benchmarks = await toolkit.compare_benchmarks(
        score,
    )
    data = [b.model_dump() for b in benchmarks]

    return {
        "current_stage": (ScorecardStage.COMPARE_BENCHMARKS.value),
        "benchmarks": data,
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Compared against {len(benchmarks)} benchmarks"]
        ),
    }


async def generate_insights(
    state: dict[str, Any],
    toolkit: SecurityScorecardToolkit,
) -> dict[str, Any]:
    """Generate LLM-powered security insights."""
    logger.info("scorecard.node.generate_insights")

    raw_scores = state.get("domain_scores", [])
    scores = [DomainScore(**s) for s in raw_scores]
    raw_trends = state.get("trends", [])
    trends = [TrendData(**t) for t in raw_trends]

    insights = await toolkit.generate_insights(
        scores,
        trends,
    )

    # LLM enhancement
    try:
        context = json.dumps(
            {
                "domain_scores": raw_scores,
                "composite": state.get(
                    "composite_score",
                    {},
                ),
                "trends": raw_trends,
                "benchmarks": state.get(
                    "benchmarks",
                    [],
                ),
            },
            default=str,
        )
        result = await llm_structured(
            system_prompt=SYSTEM_GENERATE_INSIGHTS,
            user_prompt=(f"Security posture data:\n{context}"),
            output_schema=InsightGenerationOutput,
        )
        for rec in result.strategic_recommendations:
            insights.append(
                SecurityInsight(
                    category="strategic",
                    insight=rec,
                    severity="medium",
                    recommendation=rec,
                    effort="high",
                )
            )
        improvement = result.quick_wins
    except Exception:
        logger.debug(
            "scorecard.llm_insights_fallback",
        )
        improvement = [
            s.domain.value
            for s in sorted(
                scores,
                key=lambda x: x.score,
            )[:3]
        ]

    data = [i.model_dump() for i in insights]

    return {
        "current_stage": (ScorecardStage.GENERATE_INSIGHTS.value),
        "insights": data,
        "improvement_areas": improvement,
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Generated {len(insights)} security insights"]
        ),
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: SecurityScorecardToolkit,
) -> dict[str, Any]:
    """Generate final scorecard report."""
    logger.info("scorecard.node.generate_report")

    try:
        context = json.dumps(
            {
                "overall_grade": state.get(
                    "overall_grade",
                    "",
                ),
                "composite": state.get(
                    "composite_score",
                    {},
                ),
                "insights_count": len(
                    state.get("insights", []),
                ),
                "improvement_areas": state.get(
                    "improvement_areas",
                    [],
                ),
                "benchmarks": state.get(
                    "benchmarks",
                    [],
                )[:3],
            },
            default=str,
        )
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Scorecard data:\n{context}"),
            output_schema=ScorecardReportOutput,
        )
        summary = result.executive_summary
    except Exception:
        logger.debug("scorecard.llm_report_fallback")
        grade = state.get("overall_grade", "N/A")
        summary = f"Security posture grade: {grade}"

    return {
        "current_stage": ScorecardStage.REPORT.value,
        "reasoning_chain": (state.get("reasoning_chain", []) + [f"Report: {summary[:120]}"]),
    }
