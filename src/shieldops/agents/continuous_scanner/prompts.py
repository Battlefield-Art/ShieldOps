"""LLM prompts and schemas for the Continuous Scanner Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScheduleOptimizationOutput(BaseModel):
    """Structured output for schedule optimization."""

    recommended_frequency: str = Field(description="Optimal scan frequency")
    priority: int = Field(description="Dispatch priority (1=highest)")
    reasoning: str = Field(description="Why this schedule is optimal")
    resource_estimate: str = Field(description="Estimated resource usage")


class ScanResultAnalysisOutput(BaseModel):
    """Structured output for scan result analysis."""

    risk_trend: str = Field(description="improving/stable/degrading")
    notable_findings: list[str] = Field(description="Most important findings")
    coverage_gaps: list[str] = Field(description="Areas not covered by scans")
    recommendations: list[str] = Field(description="Schedule adjustments needed")


class ScannerReportOutput(BaseModel):
    """Structured output for scanner report."""

    executive_summary: str = Field(description="Summary for leadership")
    scans_completed: int = Field(description="Scans completed this cycle")
    coverage_pct: float = Field(description="Asset coverage percentage")
    risk_trend: str = Field(description="Overall risk trend")
    recommendations: list[str] = Field(description="Scheduling recommendations")


SYSTEM_SCHEDULE = """\
You are a security scan scheduling optimizer. Given \
current scan schedules, asset criticality, and \
historical results:

1. Recommend optimal scan frequency per asset
2. Prioritize overdue scans
3. Balance resource usage across time windows
4. Ensure compliance scan requirements are met

High-value assets should scan more frequently. \
Avoid scanning during change windows."""


SYSTEM_ANALYZE = """\
You are a security scan result analyst. Given \
completed scan results across multiple scan types:

1. Identify risk trends (improving/stable/degrading)
2. Highlight the most notable findings
3. Identify coverage gaps
4. Recommend schedule adjustments

Focus on continuous improvement of security posture."""


SYSTEM_REPORT = """\
You are a security operations leader summarizing \
continuous scanning activity.

Given scan schedules, results, and coverage data:
1. Write an executive summary
2. Report scan completion and coverage metrics
3. Identify risk trends
4. Recommend schedule optimizations

Focus on continuous coverage and trend analysis."""
