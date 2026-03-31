"""MFA Bypass Detector Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class PatternInsight(BaseModel):
    """Structured output from auth pattern analysis."""

    summary: str = Field(
        description="Brief auth pattern overview",
    )
    suspicious_users: list[str] = Field(
        description="Users with suspicious auth patterns",
    )
    techniques_detected: list[str] = Field(
        description="MFA bypass techniques identified",
    )


class BypassInsight(BaseModel):
    """Structured output from bypass detection."""

    summary: str = Field(
        description="Bypass detection overview",
    )
    critical_bypasses: list[str] = Field(
        description="Critical MFA bypass attempts",
    )
    attack_chains: list[str] = Field(
        description="Identified attack chains",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of MFA bypass analysis",
    )
    key_findings: list[str] = Field(
        description="Key findings for security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are an identity security analyst reviewing "
    "MFA authentication patterns.\n"
    "1. Identify MFA fatigue attack patterns\n"
    "2. Flag suspicious session token reuse\n"
    "3. Detect rapid push notification abuse\n"
    "4. Spot impossible travel and geo anomalies"
)

SYSTEM_REPORT = (
    "You are an identity security advisor generating an "
    "executive MFA bypass analysis report.\n"
    "1. Summarize bypass attempts by technique\n"
    "2. Highlight compromised accounts\n"
    "3. Quantify the scope of MFA weaknesses\n"
    "4. Recommend MFA hardening steps"
)
