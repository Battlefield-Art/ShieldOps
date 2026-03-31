"""Endpoint Hardening Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class BaselineInsight(BaseModel):
    """Structured output from baseline compliance analysis."""

    summary: str = Field(
        description="Brief baseline compliance overview",
    )
    worst_controls: list[str] = Field(
        description="Controls with worst compliance rates",
    )
    recommendations: list[str] = Field(
        description="Priority hardening recommendations",
    )


class DeviationInsight(BaseModel):
    """Structured output from deviation analysis."""

    summary: str = Field(
        description="Deviation analysis overview",
    )
    critical_deviations: list[str] = Field(
        description="Critical deviations requiring immediate fix",
    )
    attack_vectors: list[str] = Field(
        description="Attack vectors exposed by deviations",
    )


class FixInsight(BaseModel):
    """Structured output from fix generation."""

    summary: str = Field(
        description="Fix generation overview",
    )
    high_risk_fixes: list[str] = Field(
        description="Fixes with higher risk of disruption",
    )
    dependencies: list[str] = Field(
        description="Fix dependencies to resolve first",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of hardening assessment",
    )
    key_findings: list[str] = Field(
        description="Key findings for security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_BASELINE = (
    "You are an endpoint security analyst reviewing "
    "CIS benchmark compliance results.\n"
    "1. Identify endpoints with lowest compliance scores\n"
    "2. Flag critical control failures\n"
    "3. Prioritize remediations by risk impact\n"
    "4. Recommend baseline hardening strategy"
)

SYSTEM_REPORT = (
    "You are an endpoint security advisor generating "
    "an executive hardening assessment report.\n"
    "1. Summarize compliance posture across all endpoints\n"
    "2. Highlight critical deviations and fixes applied\n"
    "3. Quantify risk reduction from hardening actions\n"
    "4. Recommend ongoing hardening maintenance plan"
)
