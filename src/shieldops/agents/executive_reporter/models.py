"""Executive Reporter Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ReporterStage(StrEnum):
    """Stages of the executive reporting pipeline."""

    COLLECT_METRICS = "collect_metrics"
    ANALYZE_TRENDS = "analyze_trends"
    SUMMARIZE_FINDINGS = "summarize_findings"
    GENERATE_RECOMMENDATIONS = "generate_recommendations"
    COMPOSE_REPORT = "compose_report"
    REPORT = "report"


class ReportType(StrEnum):
    """Types of executive reports."""

    WEEKLY_POSTURE = "weekly_posture"
    MONTHLY_EXECUTIVE = "monthly_executive"
    QUARTERLY_BOARD = "quarterly_board"
    INCIDENT_SUMMARY = "incident_summary"
    COMPLIANCE_STATUS = "compliance_status"


class ReportSection(StrEnum):
    """Sections within an executive report."""

    EXECUTIVE_SUMMARY = "executive_summary"
    POSTURE_SCORE = "posture_score"
    KEY_FINDINGS = "key_findings"
    THREAT_LANDSCAPE = "threat_landscape"
    REMEDIATION_PROGRESS = "remediation_progress"
    COMPLIANCE_STATUS = "compliance_status"
    RECOMMENDATIONS = "recommendations"


class MetricCollection(BaseModel):
    """Collected metrics from all agents."""

    category: str = ""
    metric_name: str = ""
    current_value: float = 0.0
    previous_value: float = 0.0
    unit: str = ""
    trend: str = ""


class TrendAnalysis(BaseModel):
    """Analysis of metric trends."""

    metric_name: str = ""
    direction: str = ""
    change_pct: float = 0.0
    significance: str = ""
    narrative: str = ""


class FindingSummary(BaseModel):
    """Summary of a key finding."""

    title: str = ""
    severity: str = ""
    description: str = ""
    affected_area: str = ""
    status: str = ""


class Recommendation(BaseModel):
    """Executive recommendation."""

    title: str = ""
    priority: str = ""
    rationale: str = ""
    estimated_impact: str = ""
    timeline: str = ""
    owner: str = ""


class ExecutiveReport(BaseModel):
    """The generated executive report."""

    report_type: str = ""
    reporting_period: str = ""
    executive_summary: str = ""
    posture_score: float = 0.0
    posture_grade: str = ""
    sections: dict[str, str] = Field(
        default_factory=dict,
    )
    key_metrics: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    chart_data: dict[str, Any] = Field(
        default_factory=dict,
    )


class ExecutiveReporterState(BaseModel):
    """Full state for an executive report generation."""

    # Input
    tenant_id: str = ""
    request_id: str = ""
    report_type: str = ReportType.WEEKLY_POSTURE
    reporting_period: str = ""

    # Pipeline data
    metrics_collected: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    trends_analyzed: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    findings_summarized: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report_generated: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Workflow tracking
    current_stage: str = ReporterStage.COLLECT_METRICS
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    error: str = ""
