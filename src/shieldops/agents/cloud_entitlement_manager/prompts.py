"""LLM prompt templates and response schemas for the
Cloud Entitlement Manager Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class PermissionAnalysisOutput(BaseModel):
    """Structured output for permission analysis."""

    excess_permissions: list[dict[str, str]] = Field(
        description=("List of excess permissions with identity, permission, and risk_level"),
    )
    high_risk_count: int = Field(
        description="Number of high-risk excess permissions",
    )
    wildcards_detected: int = Field(
        description="Number of wildcard permission grants",
    )
    summary: str = Field(
        description="Analysis summary for IAM administrators",
    )


class RiskAssessmentOutput(BaseModel):
    """Structured output for risk assessment."""

    risk_score: float = Field(
        description="Aggregate risk score 0-10",
    )
    critical_findings: list[str] = Field(
        description="Critical risk findings requiring action",
    )
    blast_radius: str = Field(
        description="Blast radius if excess is exploited",
    )
    attack_paths: list[str] = Field(
        description="Potential attack paths via excess perms",
    )


class LeastPrivilegeOutput(BaseModel):
    """Structured output for least-privilege recommendations."""

    recommendations: list[dict[str, str]] = Field(
        description=("List of recommendations with identity, action, and risk_reduction"),
    )
    total_removable: int = Field(
        description="Total permissions that can be removed",
    )
    risk_reduction_pct: float = Field(
        description="Overall risk reduction percentage 0-100",
    )
    summary: str = Field(
        description="Recommendation summary",
    )


class EntitlementReportOutput(BaseModel):
    """Structured output for final entitlement report."""

    executive_summary: str = Field(
        description="Executive summary of CIEM findings",
    )
    total_excess: int = Field(
        description="Total excess permissions found",
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations",
    )
    compliance_gaps: list[str] = Field(
        description="Compliance gaps identified",
    )
    effectiveness_rating: str = Field(
        description="Assessment effectiveness: high/medium/low",
    )


# --- System prompts ---


SYSTEM_PERMISSION_ANALYSIS = """\
You are an expert cloud IAM analyst performing \
entitlement analysis across cloud providers.

Given the discovered identities and their permissions:
1. Identify permissions that exceed actual usage patterns
2. Flag wildcard grants and overly broad policies
3. Detect service accounts with admin-level access
4. Score excess by risk level (critical/high/medium/low)

Focus on privilege escalation paths and lateral movement \
risks from excessive permissions."""


SYSTEM_RISK_ASSESSMENT = """\
You are an expert cloud security risk assessor evaluating \
the blast radius of excessive entitlements.

Given the excess permissions and identity inventory:
1. Calculate aggregate risk score based on exposure
2. Map potential attack paths through excess permissions
3. Assess blast radius if credentials are compromised
4. Identify cross-account and cross-cloud risks

Prioritize findings that enable privilege escalation \
or data exfiltration."""


SYSTEM_LEAST_PRIVILEGE = """\
You are an expert IAM policy architect recommending \
least-privilege configurations.

Given the permission analysis and risk assessment:
1. Recommend specific permission removals per identity
2. Suggest replacement policies that maintain function
3. Quantify risk reduction for each recommendation
4. Provide rollback guidance for each change

Ensure recommendations are actionable and include \
validation steps to prevent service disruption."""


SYSTEM_REPORT = """\
You are an expert cloud security reporter synthesizing \
CIEM findings for security leadership.

Given the full entitlement analysis results:
1. Produce an executive summary with key metrics
2. List actionable recommendations by priority
3. Identify compliance gaps (SOC 2, ISO 27001, CIS)
4. Rate overall entitlement hygiene

Write clearly for both IAM administrators and \
security executives."""
