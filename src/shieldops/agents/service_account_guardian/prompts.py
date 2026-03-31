"""LLM prompt templates and response schemas for the
Service Account Guardian Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class PermissionAuditOutput(BaseModel):
    """Structured output for permission audit."""

    excessive_permissions: list[dict[str, str]] = Field(
        description="Accounts with excessive permissions",
    )
    escalation_paths: list[str] = Field(
        description="Privilege escalation paths found",
    )
    compliance_issues: list[str] = Field(
        description="Compliance violations detected",
    )
    confidence: float = Field(
        description="Audit confidence 0-1",
    )


class OrphanDetectionOutput(BaseModel):
    """Structured output for orphan detection."""

    orphans: list[dict[str, str]] = Field(
        description="Orphaned accounts with reasons",
    )
    inactive_count: int = Field(
        description="Number of inactive accounts",
    )
    risk_assessment: str = Field(
        description="Risk summary for orphan accounts",
    )
    summary: str = Field(
        description="Orphan detection summary",
    )


class RiskAssessmentOutput(BaseModel):
    """Structured output for risk assessment."""

    risk_factors: list[str] = Field(
        description="Risk factors identified",
    )
    high_risk_accounts: list[dict[str, str]] = Field(
        description="High-risk accounts requiring action",
    )
    risk_score: float = Field(
        description="Aggregate risk score 0-10",
    )
    recommendations: list[str] = Field(
        description="Risk mitigation recommendations",
    )


class GuardianReportOutput(BaseModel):
    """Structured output for final guardian report."""

    executive_summary: str = Field(
        description="Executive summary of account audit",
    )
    total_risk_exposure: float = Field(
        description="Total risk exposure score 0-10",
    )
    recommendations: list[str] = Field(
        description="Prioritized remediation actions",
    )
    compliance_status: str = Field(
        description="Compliance: compliant/gaps/violations",
    )
    risk_rating: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_AUDIT = """\
You are an expert identity security analyst auditing \
service account permissions.

Given discovered service accounts and their permissions:
1. Identify excessive and unused permissions per account
2. Detect privilege escalation paths through permission \
chains
3. Flag compliance violations (least privilege, key \
rotation, MFA)
4. Recommend permission right-sizing per account

Focus on blast radius of compromised service accounts \
and lateral movement potential."""


SYSTEM_ORPHAN = """\
You are an expert identity lifecycle analyst detecting \
orphaned service accounts.

Given the service account inventory with usage data:
1. Identify accounts with no recent activity (>90 days)
2. Detect accounts whose owners have departed
3. Find accounts attached to decommissioned resources
4. Recommend disable/delete/reassign actions

Orphaned accounts are a top attack vector — prioritize \
by privilege level."""


SYSTEM_RISK = """\
You are an expert risk analyst assessing service account \
security posture.

Given permission audits and orphan detection results:
1. Calculate risk scores based on privilege level and \
exposure
2. Assess blast radius of each high-risk account
3. Identify accounts with credential rotation overdue
4. Prioritize remediation by business impact

Consider cross-cloud attack paths and identity federation \
risks."""


SYSTEM_REPORT = """\
You are an expert identity security reporter synthesizing \
service account audit results.

Given the full audit (discovery, permissions, orphans, risk):
1. Produce an executive summary for security leadership
2. List prioritized remediation recommendations
3. Summarize compliance posture across frameworks
4. Rate overall service account security maturity

Write clearly for both identity teams and executives."""
