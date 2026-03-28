"""LLM prompts and schemas for Agent Fleet Optimizer."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# -----------------------------------------------------------
# Response schemas
# -----------------------------------------------------------


class HealthAnalysisOutput(BaseModel):
    """LLM output for fleet health analysis."""

    health_score: float = Field(description="Fleet health score 0-100")
    patterns: list[str] = Field(description="Health patterns detected")
    concerns: list[str] = Field(description="Key health concerns")


class IssueDetectionOutput(BaseModel):
    """LLM output for issue detection."""

    issues: list[dict[str, Any]] = Field(description="Detected issues with details")
    root_causes: list[str] = Field(description="Likely root causes")
    correlations: list[str] = Field(description="Cross-agent issue correlations")


class OptimizationReportOutput(BaseModel):
    """LLM output for optimization report."""

    executive_summary: str = Field(description="Executive summary")
    top_recommendations: list[str] = Field(description="Top recommendations")
    utilization_grade: str = Field(description="A-F grade for fleet utilization")
    cost_savings_pct: float = Field(description="Estimated cost savings potential")


# -----------------------------------------------------------
# Prompt templates
# -----------------------------------------------------------

SYSTEM_HEALTH_ANALYSIS = """\
You are an expert in distributed agent fleet management. \
Analyze the health status of all agents and identify \
patterns such as correlated failures, resource \
contention, and scheduling conflicts.

Look for: stuck agents, memory leaks, cascading \
failures, and underutilized capacity."""

SYSTEM_ISSUE_DETECTION = """\
You are an SRE expert detecting issues in an agent \
fleet. Given agent health data and metrics, identify \
issues, determine root causes, and recommend actions.

Prioritize by blast radius: issues affecting many \
agents or critical agents rank higher."""

SYSTEM_OPTIMIZATION_REPORT = """\
You are a fleet operations consultant writing a report \
on agent fleet optimization. Summarize health, \
utilization, issues, and recommendations.

Focus on actionable items: what to restart, reschedule, \
scale, or disable. Include cost savings estimates."""
