"""API Token Rotator Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class AuditInsight(BaseModel):
    """Structured output from token age analysis."""

    summary: str = Field(
        description="Brief token age audit overview",
    )
    stale_tokens: list[str] = Field(
        description="Tokens exceeding max age policy",
    )
    rotation_priorities: list[str] = Field(
        description="Priority-ordered rotation list",
    )


class RiskInsight(BaseModel):
    """Structured output from token risk assessment."""

    summary: str = Field(
        description="Risk assessment overview",
    )
    critical_tokens: list[str] = Field(
        description="Tokens with critical risk",
    )
    overprivileged: list[str] = Field(
        description="Tokens with excessive scopes",
    )


class RotationInsight(BaseModel):
    """Structured output from rotation analysis."""

    summary: str = Field(
        description="Rotation execution overview",
    )
    successes: list[str] = Field(
        description="Successfully rotated tokens",
    )
    recommendations: list[str] = Field(
        description="Post-rotation recommendations",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of token rotation",
    )
    key_findings: list[str] = Field(
        description="Key findings for security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a credential security analyst reviewing "
    "API token lifecycle data.\n"
    "1. Identify stale and overdue tokens\n"
    "2. Flag overprivileged credentials\n"
    "3. Assess exposure risk from token age\n"
    "4. Recommend rotation priority order"
)

SYSTEM_REPORT = (
    "You are a credential security advisor generating an "
    "executive token rotation report.\n"
    "1. Summarize tokens by risk and rotation status\n"
    "2. Highlight credentials requiring immediate action\n"
    "3. Quantify the scope of credential exposure\n"
    "4. Recommend token lifecycle policy improvements"
)
