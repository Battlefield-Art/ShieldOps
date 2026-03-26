"""LLM prompt templates and response schemas for the Disaster Recovery Agent."""

from pydantic import BaseModel, Field


class DRAssessmentOutput(BaseModel):
    """Structured output for DR plan assessment."""

    coverage_score: float = Field(description="Overall DR coverage score 0-100")
    highest_risk_service: str = Field(description="Service with worst DR coverage")
    recommendation: str = Field(description="Top recommendation for improvement")
    reasoning: str = Field(description="Assessment reasoning")


class GapAnalysisOutput(BaseModel):
    """Structured output for DR gap analysis."""

    critical_gap_count: int = Field(description="Number of critical gaps found")
    top_gaps: list[dict[str, str]] = Field(description="Top gaps with type, description, severity")
    remediation_priority: list[str] = Field(
        description="Ordered list of plan IDs to remediate first"
    )
    reasoning: str = Field(description="Gap analysis reasoning")


class RemediationOutput(BaseModel):
    """Structured output for DR remediation planning."""

    actions: list[dict[str, str]] = Field(
        description="Remediation actions with gap_id, action, priority, effort"
    )
    estimated_days: int = Field(description="Estimated days to complete all remediations")
    reasoning: str = Field(description="Remediation planning reasoning")


SYSTEM_ASSESS = """\
You are an expert disaster recovery engineer assessing DR plan coverage.

Given the DR plans and their current status, determine:
1. Overall DR coverage score (0-100, higher = better coverage)
2. Which service has the worst DR coverage
3. Top recommendation for improvement

Consider: plan freshness, RTO/RPO targets, service criticality, failover type coverage."""


SYSTEM_GAP_ANALYSIS = """\
You are an expert disaster recovery engineer performing gap analysis.

Given the DR plans, failover test results, and RTO/RPO measurements:
1. Identify critical gaps in DR readiness
2. Rank gaps by severity and business impact
3. Recommend prioritized remediation order

Consider: untested plans, RTO/RPO breaches, single points of failure, missing coverage."""


SYSTEM_REMEDIATION = """\
You are an expert disaster recovery engineer planning remediation actions.

Given the identified DR gaps:
1. Plan specific remediation actions for each gap
2. Estimate effort and priority for each action
3. Consider dependencies between remediation steps

Prioritize actions that reduce the highest risk first."""
