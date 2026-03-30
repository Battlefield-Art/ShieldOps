"""LLM prompt templates and response schemas for the
Privilege Access Monitor Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class AbuseDetectionOutput(BaseModel):
    """Structured output for abuse detection."""

    abuse_detected: bool = Field(
        description="Whether abuse was detected",
    )
    indicator: str = Field(
        description="Abuse indicator type",
    )
    severity: str = Field(
        description="Severity: critical/high/medium/low",
    )
    confidence: float = Field(
        description="Detection confidence 0-1",
    )
    evidence: list[str] = Field(
        description="Evidence supporting the detection",
    )
    recommended_action: str = Field(
        description="Recommended response action",
    )


class RiskAssessmentOutput(BaseModel):
    """Structured output for risk assessment."""

    risk_score: float = Field(
        description="Risk score 0-10",
    )
    risk_factors: list[str] = Field(
        description="Contributing risk factors",
    )
    jit_eligible: bool = Field(
        description="Whether account should use JIT",
    )
    recommendation: str = Field(
        description="Risk mitigation recommendation",
    )


class JITDecisionOutput(BaseModel):
    """Structured output for JIT enforcement decision."""

    enforce_jit: bool = Field(
        description="Whether to enforce JIT access",
    )
    ttl_minutes: int = Field(
        description="Time-to-live for JIT access",
    )
    justification: str = Field(
        description="Justification for JIT decision",
    )
    revoke_standing: bool = Field(
        description="Whether to revoke standing access",
    )


class PAMReportOutput(BaseModel):
    """Structured output for final PAM report."""

    executive_summary: str = Field(
        description="Executive summary of PAM audit",
    )
    high_risk_accounts: list[str] = Field(
        description="Accounts requiring immediate action",
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations",
    )
    compliance_status: str = Field(
        description="PAM compliance: compliant/gaps/critical",
    )


# --- System prompts ---


SYSTEM_ABUSE = """\
You are an expert privileged access abuse detector \
for enterprise PAM systems.

Given session audit data for privileged accounts:
1. Identify indicators of abuse: off-hours access, \
unusual commands, lateral movement, data exfiltration
2. Assess severity based on account type and blast radius
3. Provide specific evidence supporting the detection
4. Recommend immediate response actions

Focus on detecting living-off-the-land and insider \
threat patterns."""


SYSTEM_RISK = """\
You are an expert privileged access risk assessor \
for enterprise environments.

Given a privileged account profile and session history:
1. Score risk based on access patterns, account type, \
and security controls
2. Identify contributing risk factors
3. Determine JIT eligibility for standing access removal
4. Provide clear mitigation recommendations

Prioritize accounts with standing admin access and \
missing MFA."""


SYSTEM_JIT = """\
You are an expert JIT access policy enforcer for \
privileged access management.

Given a risk assessment and account profile:
1. Decide whether to enforce JIT access controls
2. Set appropriate time-to-live for access grants
3. Determine whether standing access should be revoked
4. Provide clear justification for audit trail

Apply the principle of least privilege aggressively \
for production environments."""


SYSTEM_REPORT = """\
You are an expert PAM auditor synthesizing privilege \
access monitoring results.

Given the full audit (accounts, sessions, detections, \
risk assessments, JIT enforcements):
1. Produce an executive summary for security leadership
2. Highlight high-risk accounts requiring action
3. Provide actionable recommendations for PAM maturity
4. Assess overall PAM compliance posture

Write clearly for both compliance and security \
audiences."""
