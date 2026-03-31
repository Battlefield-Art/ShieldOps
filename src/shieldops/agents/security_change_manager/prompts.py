"""Security Change Manager Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class RiskInsight(BaseModel):
    """Structured output from change risk assessment."""

    summary: str = Field(
        description="Brief change risk overview",
    )
    high_risk_factors: list[str] = Field(
        description="Factors contributing to elevated risk",
    )
    recommended_mitigations: list[str] = Field(
        description="Recommended risk mitigations",
    )


class DependencyInsight(BaseModel):
    """Structured output from dependency impact analysis."""

    summary: str = Field(
        description="Dependency impact overview",
    )
    critical_paths: list[str] = Field(
        description="Critical dependency paths affected",
    )
    conflict_risks: list[str] = Field(
        description="Potential dependency conflicts",
    )


class ApprovalInsight(BaseModel):
    """Structured output from approval decision analysis."""

    summary: str = Field(
        description="Approval decision rationale",
    )
    conditions: list[str] = Field(
        description="Conditions for approval",
    )
    escalation_reasons: list[str] = Field(
        description="Reasons for escalation if any",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of change management cycle",
    )
    key_findings: list[str] = Field(
        description="Key findings for operations team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_RISK = (
    "You are a security-aware change management advisor "
    "assessing change risk.\n"
    "1. Evaluate blast radius and affected services\n"
    "2. Identify security and compliance implications\n"
    "3. Score risk based on environment and change type\n"
    "4. Recommend mitigations for high-risk changes"
)

SYSTEM_REPORT = (
    "You are a change management advisor generating an "
    "executive change cycle report.\n"
    "1. Summarize changes by risk level and outcome\n"
    "2. Highlight rejected or escalated changes\n"
    "3. Report on rollout health metrics\n"
    "4. Recommend process improvements"
)
