"""Executive Reporter Agent — Tool functions."""

from __future__ import annotations

from typing import Any

import structlog

from .models import (
    FindingSummary,
    MetricCollection,
    Recommendation,
    TrendAnalysis,
)

logger = structlog.get_logger()

# Representative security metrics
_BASELINE_METRICS: list[dict[str, Any]] = [
    {
        "cat": "posture",
        "name": "Security Posture Score",
        "current": 68.5,
        "previous": 65.2,
        "unit": "score",
    },
    {
        "cat": "incidents",
        "name": "Incident Count",
        "current": 23,
        "previous": 31,
        "unit": "count",
    },
    {
        "cat": "incidents",
        "name": "Mean Time to Detect",
        "current": 4.2,
        "previous": 6.8,
        "unit": "hours",
    },
    {
        "cat": "incidents",
        "name": "Mean Time to Respond",
        "current": 8.5,
        "previous": 12.1,
        "unit": "hours",
    },
    {
        "cat": "vulnerabilities",
        "name": "Critical Vulnerabilities",
        "current": 12,
        "previous": 18,
        "unit": "count",
    },
    {
        "cat": "vulnerabilities",
        "name": "Remediation Rate",
        "current": 78.0,
        "previous": 72.0,
        "unit": "percent",
    },
    {
        "cat": "compliance",
        "name": "SOC 2 Coverage",
        "current": 89.0,
        "previous": 85.0,
        "unit": "percent",
    },
    {
        "cat": "compliance",
        "name": "HIPAA Coverage",
        "current": 82.0,
        "previous": 79.0,
        "unit": "percent",
    },
    {
        "cat": "identity",
        "name": "MFA Adoption",
        "current": 94.0,
        "previous": 88.0,
        "unit": "percent",
    },
    {
        "cat": "cloud",
        "name": "Cloud Misconfigs",
        "current": 45,
        "previous": 62,
        "unit": "count",
    },
]

# Representative findings
_BASELINE_FINDINGS: list[dict[str, Any]] = [
    {
        "title": "Critical S3 Bucket Exposure",
        "severity": "critical",
        "desc": "12 S3 buckets with public access",
        "area": "cloud",
        "status": "remediating",
    },
    {
        "title": "Stale Service Accounts",
        "severity": "high",
        "desc": "34 unused service accounts > 90 days",
        "area": "identity",
        "status": "open",
    },
    {
        "title": "Unpatched Log4j Instances",
        "severity": "high",
        "desc": "8 services still vulnerable",
        "area": "application",
        "status": "in_progress",
    },
    {
        "title": "Insufficient DDoS Protection",
        "severity": "medium",
        "desc": "No scrubbing service for API tier",
        "area": "network",
        "status": "planned",
    },
]


class ExecutiveReporterToolkit:
    """Toolkit for executive report generation."""

    def __init__(
        self,
        agent_registry: Any | None = None,
        metrics_store: Any | None = None,
        findings_db: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._agent_registry = agent_registry
        self._metrics_store = metrics_store
        self._findings_db = findings_db
        self._repository = repository

    async def collect_metrics(
        self,
        tenant_id: str,
        report_type: str = "",
    ) -> list[MetricCollection]:
        """Collect metrics from all agents."""
        logger.info(
            "executive_reporter.collect_metrics",
            tenant_id=tenant_id,
            report_type=report_type,
        )
        if self._metrics_store is not None:
            try:
                return await self._metrics_store.get_metrics(
                    tenant_id,
                )
            except Exception:
                logger.warning(
                    "executive_reporter.metrics_fb",
                )

        metrics: list[MetricCollection] = []
        for m in _BASELINE_METRICS:
            prev = m["previous"]
            curr = m["current"]
            if curr > prev:
                if m["unit"] == "count" and "Vuln" in m["name"] or m["unit"] == "count":
                    trend = "degrading"
                else:
                    trend = "improving"
            elif curr < prev:
                if m["unit"] == "count" and (
                    "Incident" in m["name"] or "Vuln" in m["name"] or "Misconfig" in m["name"]
                ):
                    trend = "improving"
                else:
                    trend = "degrading"
            else:
                trend = "stable"

            metrics.append(
                MetricCollection(
                    category=m["cat"],
                    metric_name=m["name"],
                    current_value=curr,
                    previous_value=prev,
                    unit=m["unit"],
                    trend=trend,
                )
            )
        return metrics

    async def analyze_trends(
        self,
        metrics: list[MetricCollection],
    ) -> list[TrendAnalysis]:
        """Analyze metric trends."""
        logger.info(
            "executive_reporter.analyze_trends",
            metric_count=len(metrics),
        )
        analyses: list[TrendAnalysis] = []
        for m in metrics:
            prev = m.previous_value
            change = (
                round(
                    (m.current_value - prev) / prev * 100,
                    1,
                )
                if prev
                else 0.0
            )
            significance = (
                "significant" if abs(change) > 10 else "moderate" if abs(change) > 5 else "minor"
            )
            analyses.append(
                TrendAnalysis(
                    metric_name=m.metric_name,
                    direction=m.trend,
                    change_pct=change,
                    significance=significance,
                    narrative=(
                        f"{m.metric_name}: "
                        f"{m.previous_value} -> "
                        f"{m.current_value} {m.unit} "
                        f"({change:+.1f}%)"
                    ),
                )
            )
        return analyses

    async def summarize_findings(
        self,
        tenant_id: str,
    ) -> list[FindingSummary]:
        """Collect and summarize key findings."""
        logger.info(
            "executive_reporter.findings",
            tenant_id=tenant_id,
        )
        if self._findings_db is not None:
            try:
                return await self._findings_db.get_findings(
                    tenant_id,
                )
            except Exception:
                logger.warning(
                    "executive_reporter.findings_fb",
                )

        return [
            FindingSummary(
                title=f["title"],
                severity=f["severity"],
                description=f["desc"],
                affected_area=f["area"],
                status=f["status"],
            )
            for f in _BASELINE_FINDINGS
        ]

    async def generate_recommendations(
        self,
        findings: list[FindingSummary],
        trends: list[TrendAnalysis],
    ) -> list[Recommendation]:
        """Generate recommendations from findings."""
        logger.info(
            "executive_reporter.recommendations",
            finding_count=len(findings),
        )
        recs: list[Recommendation] = []
        for f in findings:
            recs.append(
                Recommendation(
                    title=f"Remediate: {f.title}",
                    priority=f.severity,
                    rationale=f.description,
                    estimated_impact=("Reduces attack surface"),
                    timeline=(
                        "7 days"
                        if f.severity == "critical"
                        else "30 days"
                        if f.severity == "high"
                        else "90 days"
                    ),
                    owner="security-team",
                )
            )
        return recs
