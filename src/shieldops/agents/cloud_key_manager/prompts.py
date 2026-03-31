"""Cloud Key Manager Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class RotationInsight(BaseModel):
    """Structured output from key rotation analysis."""

    summary: str = Field(
        description="Brief key rotation overview",
    )
    overdue_keys: list[str] = Field(
        description="Keys overdue for rotation",
    )
    compliance_gaps: list[str] = Field(
        description="Compliance gaps identified",
    )


class RiskInsight(BaseModel):
    """Structured output from key risk assessment."""

    summary: str = Field(
        description="Key risk assessment overview",
    )
    critical_findings: list[str] = Field(
        description="Critical risk findings",
    )
    quantum_risks: list[str] = Field(
        description="Quantum computing risk factors",
    )


class UsageInsight(BaseModel):
    """Structured output from key usage analysis."""

    summary: str = Field(
        description="Key usage analysis overview",
    )
    unused_keys: list[str] = Field(
        description="Keys with no recent activity",
    )
    recommendations: list[str] = Field(
        description="Usage optimization recommendations",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of key management",
    )
    key_findings: list[str] = Field(
        description="Key findings for security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a cloud KMS security analyst reviewing "
    "key management practices.\n"
    "1. Identify keys overdue for rotation\n"
    "2. Flag weak or deprecated algorithms\n"
    "3. Detect unused or orphaned keys\n"
    "4. Assess crypto-agility and quantum readiness"
)

SYSTEM_REPORT = (
    "You are a cloud key management advisor generating an "
    "executive KMS security report.\n"
    "1. Summarize key risks by provider and severity\n"
    "2. Highlight keys requiring immediate rotation\n"
    "3. Quantify compliance posture across clouds\n"
    "4. Recommend key lifecycle improvements"
)
