"""LLM prompt templates and schemas for Service Health Monitor."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DegradationAnalysisOutput(BaseModel):
    """Structured output for degradation analysis."""

    severity: str = Field(
        description="Overall severity: critical/high/warning/info",
    )
    root_cause_hypothesis: str = Field(
        description="Likely root cause of degradation",
    )
    affected_services: list[str] = Field(
        description="Services affected by the degradation",
    )
    recommended_actions: list[str] = Field(
        description="Ordered remediation actions",
    )
    cascade_risk: str = Field(
        description="Risk of cascading failure: high/medium/low",
    )
    confidence: float = Field(
        description="Confidence in analysis 0.0-1.0",
    )


class HealthReportOutput(BaseModel):
    """Structured output for health report generation."""

    executive_summary: str = Field(
        description="1-2 sentence executive summary",
    )
    services_at_risk: list[str] = Field(
        description="Services at risk of failure",
    )
    key_findings: list[str] = Field(
        description="Key findings from monitoring",
    )
    recommendations: list[str] = Field(
        description="Prioritized recommendations",
    )


class RemediationPlanOutput(BaseModel):
    """Structured output for remediation planning."""

    action_type: str = Field(
        description="Type: restart/scale/failover/rollback",
    )
    priority: str = Field(
        description="Priority: immediate/high/medium/low",
    )
    steps: list[str] = Field(
        description="Ordered steps for remediation",
    )
    estimated_recovery_minutes: int = Field(
        description="Estimated time to recover",
    )
    rollback_plan: str = Field(
        description="Rollback plan if remediation fails",
    )


SYSTEM_DEGRADATION = """\
You are an expert SRE analyzing service degradation.

Given the health checks and degradation events:
1. Assess overall severity across all services
2. Hypothesize the root cause based on patterns
3. Identify services at risk of cascading failure
4. Recommend specific, prioritized actions
5. Estimate cascade risk to downstream services

Use dependency analysis to assess blast radius."""


SYSTEM_REPORT = """\
You are an expert SRE generating a health report.

Given collected health checks and dependency data:
1. Provide a concise executive summary
2. Identify services at risk of failure
3. Highlight key findings and trends
4. Recommend prioritized actions

Focus on actionable insights, not raw data."""


SYSTEM_REMEDIATION = """\
You are an expert SRE planning automated remediation.

Given degradation events and service context:
1. Determine the appropriate remediation action
2. Prioritize based on service tier and impact
3. Provide ordered execution steps
4. Estimate recovery time
5. Include a rollback plan

Follow the principle of least-disruptive action."""
