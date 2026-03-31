"""LLM prompt templates and response schemas for the
Access Certification Engine Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class UsageAnalysisOutput(BaseModel):
    """Structured output for entitlement usage analysis."""

    dormant_entitlements: list[dict[str, str]] = Field(
        description=("List of dormant entitlements with user, resource, days_unused"),
    )
    excess_permissions: list[dict[str, str]] = Field(
        description="Permissions exceeding least-privilege baseline",
    )
    sod_violations: list[dict[str, str]] = Field(
        description="Segregation of duties conflicts found",
    )
    risk_score: float = Field(
        description="Overall access risk score 0-10",
    )


class ExcessIdentificationOutput(BaseModel):
    """Structured output for excess permission detection."""

    permission_id: str = Field(
        description="Identifier for the excess permission",
    )
    reason: str = Field(
        description="Reason this permission is considered excess",
    )
    risk_level: str = Field(
        description="Risk: critical/high/medium/low",
    )
    confidence: float = Field(
        description="Confidence in excess classification 0-1",
    )
    recommended_action: str = Field(
        description="Recommended action: revoke/modify/monitor",
    )
    sod_conflict: bool = Field(
        description="Whether permission creates SOD conflict",
    )


class CertificationReportOutput(BaseModel):
    """Structured output for the certification report."""

    executive_summary: str = Field(
        description="Executive summary of access certification",
    )
    rubber_stamp_rate: float = Field(
        description="Percentage of reviews auto-approved 0-100",
    )
    top_risks: list[str] = Field(
        description="Highest-risk access findings",
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations",
    )
    compliance_status: str = Field(
        description="Compliance: compliant/at-risk/non-compliant",
    )


# --- System prompts ---


SYSTEM_USAGE = """\
You are an expert identity governance analyst reviewing \
entitlement usage patterns for access certification.

Given the collected entitlements and usage metrics:
1. Identify dormant entitlements unused for 30+ days
2. Detect permissions exceeding least-privilege baseline
3. Find segregation of duties conflicts (e.g., creator \
and approver roles on same user)
4. Score overall access risk for each user

Focus on high-privilege accounts and service accounts \
that accumulate permissions over time."""


SYSTEM_EXCESS = """\
You are an expert IAM security analyst identifying \
excess permissions for access review.

Given a specific entitlement with usage data:
1. Determine if the permission exceeds least-privilege
2. Check for segregation of duties violations
3. Assess risk based on resource sensitivity and role
4. Recommend revoke, modify, or continued monitoring

Err on the side of flagging for review: over-provisioned \
access is a top attack vector."""


SYSTEM_REPORT = """\
You are an expert identity governance reporter \
synthesizing access certification results.

Given the full certification campaign (entitlements, \
usage analysis, excess permissions, reviews):
1. Produce an executive summary for compliance teams
2. Calculate rubber-stamp detection rate
3. Highlight the highest-risk access findings
4. Recommend governance improvements

Write for both CISO-level and compliance auditor \
audiences."""
