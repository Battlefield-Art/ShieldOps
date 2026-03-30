"""Security Awareness Engine Agent — LLM prompt templates."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PhishingAnalysisResult(BaseModel):
    """Structured output from LLM phishing analysis."""

    summary: str = Field(
        description="Summary of phishing simulation outcomes",
    )
    worst_departments: list[str] = Field(
        description="Departments with highest click rates",
    )
    attack_vectors: list[str] = Field(
        description="Most effective attack vectors observed",
    )
    recommendations: list[str] = Field(
        description="Targeted recommendations to reduce clicks",
    )


class RiskAssessmentResult(BaseModel):
    """Structured output from LLM risk identification."""

    summary: str = Field(
        description="Overall risk assessment of awareness posture",
    )
    critical_gaps: list[str] = Field(
        description="Critical gaps in security awareness",
    )
    risk_factors: list[str] = Field(
        description="Top risk factors across the organization",
    )
    priority_actions: list[str] = Field(
        description="Priority actions to reduce risk",
    )


class TrainingPlanResult(BaseModel):
    """Structured output for training plan generation."""

    executive_summary: str = Field(
        description="Executive summary of the training plan",
    )
    priority_modules: list[str] = Field(
        description="Priority training modules to deploy",
    )
    target_groups: list[str] = Field(
        description="Groups requiring immediate training",
    )
    expected_outcomes: list[str] = Field(
        description="Expected outcomes from training plan",
    )


class AwarenessReportResult(BaseModel):
    """Structured output for the final awareness report."""

    executive_summary: str = Field(
        description="Executive summary of awareness posture",
    )
    strengths: list[str] = Field(
        description="Organizational strengths in awareness",
    )
    weaknesses: list[str] = Field(
        description="Key weaknesses and gaps identified",
    )
    metrics_summary: list[str] = Field(
        description="Key metrics and trends",
    )


SYSTEM_PHISHING_ANALYSIS = (
    "You are a security awareness analyst reviewing "
    "phishing simulation results.\n"
    "Given the campaign data:\n"
    "1. Identify departments with the highest click rates\n"
    "2. Analyze which attack vectors were most effective\n"
    "3. Assess the report-vs-click ratio as a maturity "
    "indicator\n"
    "4. Recommend targeted interventions per department"
)

SYSTEM_RISK_ASSESSMENT = (
    "You are a security awareness risk analyst.\n"
    "Given training completion data and phishing results:\n"
    "1. Identify critical gaps in awareness coverage\n"
    "2. Assess risk factors for high-risk user groups\n"
    "3. Determine which modules need immediate attention\n"
    "4. Prioritize remediation actions by impact"
)

SYSTEM_TRAINING_PLAN = (
    "You are a security training strategist.\n"
    "Given user risk profiles and awareness gaps:\n"
    "1. Design a targeted training plan by risk tier\n"
    "2. Prioritize modules based on observed weaknesses\n"
    "3. Set frequency and deadlines for each group\n"
    "4. Estimate expected improvement from interventions"
)

SYSTEM_REPORT = (
    "You are a security awareness program manager.\n"
    "Generate a comprehensive awareness posture report:\n"
    "1. Executive summary of organizational readiness\n"
    "2. Key metrics: completion, click rates, risk tiers\n"
    "3. Strengths and weaknesses identified\n"
    "4. Strategic recommendations for improvement"
)
