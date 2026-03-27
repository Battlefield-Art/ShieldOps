"""Executive Reporter Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    ExecutiveReport,
    FindingSummary,
    MetricCollection,
    ReporterStage,
    TrendAnalysis,
)
from .prompts import (
    SYSTEM_ANALYZE_TRENDS,
    SYSTEM_COMPOSE_REPORT,
    SYSTEM_GENERATE_RECOMMENDATIONS,
    SYSTEM_SUMMARIZE_FINDINGS,
    FindingSummaryOutput,
    RecommendationOutput,
    ReportCompositionOutput,
    TrendNarrativeOutput,
)
from .tools import ExecutiveReporterToolkit

logger = structlog.get_logger()


async def collect_metrics(
    state: dict[str, Any],
    toolkit: ExecutiveReporterToolkit,
) -> dict[str, Any]:
    """Collect metrics from all agents."""
    logger.info("executive_reporter.node.collect")

    tenant_id = state.get("tenant_id", "")
    report_type = state.get(
        "report_type",
        "weekly_posture",
    )
    metrics = await toolkit.collect_metrics(
        tenant_id,
        report_type,
    )
    data = [m.model_dump() for m in metrics]

    return {
        "current_stage": (ReporterStage.COLLECT_METRICS.value),
        "metrics_collected": data,
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Collected {len(metrics)} security metrics"]
        ),
    }


async def analyze_trends(
    state: dict[str, Any],
    toolkit: ExecutiveReporterToolkit,
) -> dict[str, Any]:
    """Analyze metric trends with LLM narratives."""
    logger.info("executive_reporter.node.trends")

    raw = state.get("metrics_collected", [])
    metrics = [MetricCollection(**m) for m in raw]
    trends = await toolkit.analyze_trends(metrics)

    # LLM narrative generation for each trend
    try:
        context = json.dumps(
            [t.model_dump() for t in trends],
            default=str,
        )
        result = await llm_structured(
            system_prompt=SYSTEM_ANALYZE_TRENDS,
            user_prompt=(f"Security metric trends:\n{context}"),
            output_schema=TrendNarrativeOutput,
        )
        # Enrich trends with LLM narratives
        for i, narrative in enumerate(
            result.narratives,
        ):
            if i < len(trends):
                trends[i].narrative = narrative
        reasoning = f"Trend analysis: {result.overall_direction}"
    except Exception:
        logger.debug(
            "executive_reporter.llm_trends_fb",
        )
        reasoning = f"Analyzed {len(trends)} metric trends"

    data = [t.model_dump() for t in trends]

    return {
        "current_stage": (ReporterStage.ANALYZE_TRENDS.value),
        "trends_analyzed": data,
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def summarize_findings(
    state: dict[str, Any],
    toolkit: ExecutiveReporterToolkit,
) -> dict[str, Any]:
    """Summarize key findings with LLM."""
    logger.info("executive_reporter.node.findings")

    tenant_id = state.get("tenant_id", "")
    findings = await toolkit.summarize_findings(
        tenant_id,
    )

    # LLM enhancement for each finding
    for finding in findings:
        try:
            result = await llm_structured(
                system_prompt=(SYSTEM_SUMMARIZE_FINDINGS),
                user_prompt=(
                    f"Finding: {finding.title}\n"
                    f"Severity: {finding.severity}\n"
                    f"Details: {finding.description}\n"
                    f"Area: {finding.affected_area}"
                ),
                output_schema=FindingSummaryOutput,
            )
            finding.title = result.title
            finding.description = result.executive_description
        except Exception:
            logger.debug(
                "executive_reporter.llm_finding_fb",
                title=finding.title,
            )

    data = [f.model_dump() for f in findings]

    return {
        "current_stage": (ReporterStage.SUMMARIZE_FINDINGS.value),
        "findings_summarized": data,
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Summarized {len(findings)} key findings"]
        ),
    }


async def generate_recommendations(
    state: dict[str, Any],
    toolkit: ExecutiveReporterToolkit,
) -> dict[str, Any]:
    """Generate LLM-powered recommendations."""
    logger.info("executive_reporter.node.recs")

    raw_findings = state.get(
        "findings_summarized",
        [],
    )
    findings = [FindingSummary(**f) for f in raw_findings]
    raw_trends = state.get("trends_analyzed", [])
    trends = [TrendAnalysis(**t) for t in raw_trends]

    recs = await toolkit.generate_recommendations(
        findings,
        trends,
    )

    # LLM enhancement for each recommendation
    for rec in recs:
        try:
            result = await llm_structured(
                system_prompt=(SYSTEM_GENERATE_RECOMMENDATIONS),
                user_prompt=(
                    f"Finding: {rec.rationale}\n"
                    f"Priority: {rec.priority}\n"
                    f"Generate an executive "
                    f"recommendation."
                ),
                output_schema=RecommendationOutput,
            )
            rec.title = result.title
            rec.rationale = result.rationale
            rec.estimated_impact = result.estimated_impact
            rec.timeline = result.timeline
        except Exception:
            logger.debug(
                "executive_reporter.llm_rec_fb",
                title=rec.title,
            )

    data = [r.model_dump() for r in recs]

    return {
        "current_stage": (ReporterStage.GENERATE_RECOMMENDATIONS.value),
        "recommendations": data,
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Generated {len(recs)} recommendations"]
        ),
    }


async def compose_report(
    state: dict[str, Any],
    toolkit: ExecutiveReporterToolkit,
) -> dict[str, Any]:
    """Compose the full executive report."""
    logger.info("executive_reporter.node.compose")

    report_type = state.get(
        "report_type",
        "weekly_posture",
    )
    period = state.get(
        "reporting_period",
        "This week",
    )

    # Compose with LLM
    try:
        context = json.dumps(
            {
                "report_type": report_type,
                "period": period,
                "metrics": state.get(
                    "metrics_collected",
                    [],
                )[:8],
                "trends": state.get(
                    "trends_analyzed",
                    [],
                )[:5],
                "findings": state.get(
                    "findings_summarized",
                    [],
                )[:5],
                "recommendations": state.get(
                    "recommendations",
                    [],
                )[:5],
            },
            default=str,
        )
        result = await llm_structured(
            system_prompt=SYSTEM_COMPOSE_REPORT,
            user_prompt=(f"Compose executive report:\n{context}"),
            output_schema=ReportCompositionOutput,
        )
        exec_summary = result.executive_summary
        posture_narrative = result.posture_narrative
        threat_landscape = result.threat_landscape
    except Exception:
        logger.debug(
            "executive_reporter.llm_compose_fb",
        )
        exec_summary = f"Security posture report for {period}."
        posture_narrative = "See metrics below."
        threat_landscape = "See findings below."

    # Build the report
    metrics = state.get("metrics_collected", [])
    posture_score = 0.0
    for m in metrics:
        if m.get("metric_name") == ("Security Posture Score"):
            posture_score = m.get(
                "current_value",
                0.0,
            )
            break

    report = ExecutiveReport(
        report_type=report_type,
        reporting_period=period,
        executive_summary=exec_summary,
        posture_score=posture_score,
        posture_grade=(
            "A"
            if posture_score >= 85
            else "B"
            if posture_score >= 70
            else "C"
            if posture_score >= 55
            else "D"
        ),
        sections={
            "executive_summary": exec_summary,
            "posture_score": posture_narrative,
            "threat_landscape": threat_landscape,
        },
        key_metrics=metrics[:8],
        findings=state.get(
            "findings_summarized",
            [],
        ),
        recommendations=state.get(
            "recommendations",
            [],
        ),
        chart_data={
            "trends": state.get(
                "trends_analyzed",
                [],
            ),
        },
    )

    return {
        "current_stage": (ReporterStage.COMPOSE_REPORT.value),
        "report_generated": report.model_dump(),
        "reasoning_chain": (
            state.get("reasoning_chain", [])
            + [f"Composed {report_type} report with {len(report.findings)} findings"]
        ),
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: ExecutiveReporterToolkit,
) -> dict[str, Any]:
    """Finalize the executive report."""
    logger.info("executive_reporter.node.finalize")

    report = state.get("report_generated", {})
    summary = report.get(
        "executive_summary",
        "Report generated.",
    )

    return {
        "current_stage": (ReporterStage.REPORT.value),
        "reasoning_chain": (state.get("reasoning_chain", []) + [f"Final: {summary[:120]}"]),
    }
