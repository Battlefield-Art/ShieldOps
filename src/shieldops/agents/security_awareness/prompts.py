"""LLM prompt templates and response schemas for Security Awareness."""

from __future__ import annotations

from pydantic import BaseModel, Field


class BaselineOutput(BaseModel):
    """Structured output for baseline assessment."""

    overall_readiness: str = Field(
        description="Current awareness posture: strong/moderate/weak",
    )
    phishing_susceptibility_pct: float = Field(
        description="Estimated phishing susceptibility 0-100",
    )
    training_gap_areas: list[str] = Field(
        description="Areas needing training coverage",
    )
    priority_departments: list[str] = Field(
        description="Departments needing immediate attention",
    )


class SimulationAnalysisOutput(BaseModel):
    """Structured output for simulation result analysis."""

    failure_rate_pct: float = Field(
        description="Overall simulation failure rate 0-100",
    )
    top_failure_patterns: list[str] = Field(
        description="Most common failure patterns observed",
    )
    highest_risk_departments: list[str] = Field(
        description="Departments with worst performance",
    )
    improvement_vs_prior: str = Field(
        description="Improvement trend: improved/stable/declined",
    )


class TrainingAnalysisOutput(BaseModel):
    """Structured output for training status analysis."""

    completion_rate_pct: float = Field(
        description="Overall training completion rate 0-100",
    )
    avg_score_pct: float = Field(
        description="Average training score 0-100",
    )
    overdue_count: int = Field(
        description="Number of overdue training assignments",
    )
    effectiveness_rating: str = Field(
        description="Training effectiveness: high/moderate/low",
    )


class RiskScoringOutput(BaseModel):
    """Structured output for risk scoring analysis."""

    high_risk_user_count: int = Field(
        description="Number of users in high/critical risk tier",
    )
    avg_risk_score: float = Field(
        description="Average risk score 0-100 across all users",
    )
    risk_distribution: dict[str, int] = Field(
        description="Count of users per risk tier",
    )
    top_risk_factors: list[str] = Field(
        description="Most common risk factors",
    )


class RecommendationOutput(BaseModel):
    """Structured output for improvement recommendations."""

    recommendations: list[str] = Field(
        description="Prioritized improvement recommendations",
    )
    quick_wins: list[str] = Field(
        description="Low-effort high-impact actions",
    )
    long_term_initiatives: list[str] = Field(
        description="Strategic long-term improvements",
    )


class ReportOutput(BaseModel):
    """Structured output for awareness program report."""

    executive_summary: str = Field(
        description="One-paragraph executive summary",
    )
    overall_score: float = Field(
        description="Overall program score 0-100",
    )
    key_findings: list[str] = Field(
        description="Key findings from the assessment",
    )
    action_items: list[str] = Field(
        description="Recommended action items",
    )


SYSTEM_ASSESS_BASELINE = """\
You are an expert security awareness program assessor.

Given the organization's phishing simulation history \
and training records:
1. Evaluate current awareness posture
2. Identify phishing susceptibility rate
3. Highlight training coverage gaps
4. Prioritize departments needing attention

Be data-driven and objective in your assessment."""


SYSTEM_ANALYZE_SIMULATIONS = """\
You are an expert analyzing phishing simulation results.

Given the simulation data:
1. Calculate failure rates by type and department
2. Identify common failure patterns
3. Compare against prior campaign performance
4. Flag highest-risk groups

Focus on actionable patterns, not individual blame."""


SYSTEM_ANALYZE_TRAINING = """\
You are an expert evaluating security training programs.

Given the training completion and score data:
1. Assess overall completion and pass rates
2. Identify overdue assignments
3. Evaluate training effectiveness
4. Recommend curriculum adjustments

Prioritize training that reduces real phishing risk."""


SYSTEM_SCORE_RISK = """\
You are an expert in human risk quantification \
for cybersecurity.

Given phishing results and training data per user:
1. Calculate composite risk scores
2. Classify users into risk tiers
3. Identify top risk factors
4. Provide per-department risk summaries

Score fairly — consider both failures and improvements."""


SYSTEM_RECOMMEND = """\
You are an expert security awareness strategist.

Given the full risk assessment:
1. Prioritize improvement recommendations
2. Identify quick wins vs long-term initiatives
3. Suggest targeted interventions for high-risk groups
4. Recommend simulation cadence and training updates

Focus on measurable risk reduction."""


SYSTEM_REPORT = """\
You are an expert generating a security awareness \
program report.

Given all assessment results:
1. Executive summary for leadership
2. Overall program health score
3. Key findings and risk highlights
4. Prioritized action items

Write for a CISO audience — concise, data-backed, \
and actionable."""
