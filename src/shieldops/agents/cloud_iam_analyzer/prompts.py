"""LLM prompt templates and response schemas for the
Cloud IAM Analyzer Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class PermissionAnalysisOutput(BaseModel):
    """Structured output for permission analysis."""

    overprivileged_principals: list[str] = Field(
        description="Principals with excessive permissions",
    )
    unused_permission_count: int = Field(
        description="Total unused permissions found",
    )
    admin_access_principals: list[str] = Field(
        description="Principals with admin/root access",
    )
    summary: str = Field(
        description="Permission analysis summary",
    )


class RiskDetectionOutput(BaseModel):
    """Structured output for IAM risk detection."""

    findings: list[dict[str, str]] = Field(
        description="Risk findings with category, level, description",
    )
    critical_count: int = Field(
        description="Number of critical risk findings",
    )
    top_risks: list[str] = Field(
        description="Top risk descriptions",
    )


class CloudComparisonOutput(BaseModel):
    """Structured output for cross-cloud comparison."""

    consistency_score: float = Field(
        description="Cross-cloud policy consistency 0-1",
    )
    gaps: list[str] = Field(
        description="Policy gaps across providers",
    )
    recommendations: list[str] = Field(
        description="Cross-cloud alignment recommendations",
    )


class IAMReportOutput(BaseModel):
    """Structured output for IAM analysis report."""

    executive_summary: str = Field(
        description="Executive summary of IAM posture",
    )
    risk_score: float = Field(
        description="Overall IAM risk score 0-10",
    )
    recommendations: list[str] = Field(
        description="Prioritized IAM recommendations",
    )
    compliance_gaps: list[str] = Field(
        description="Compliance framework gaps found",
    )


# --- System prompts ---


SYSTEM_PERMISSIONS = """\
You are an expert cloud IAM analyst evaluating \
permission configurations across AWS, GCP, and Azure.

Given IAM policies and usage data:
1. Identify overprivileged principals with unused \
permissions
2. Detect admin/root access and cross-account trust \
relationships
3. Evaluate least-privilege adherence per principal
4. Recommend permission right-sizing actions

Apply CIS Benchmark and cloud-native best practices \
for each provider."""


SYSTEM_RISKS = """\
You are an expert IAM security analyst detecting \
identity-related risks across multi-cloud environments.

Given permission analyses and policy configurations:
1. Detect privilege escalation paths and lateral \
movement risks
2. Identify orphaned accounts and stale credentials
3. Flag policy misconfigurations and overly permissive \
resource scopes
4. Assess cross-account trust chain risks

Prioritize findings by exploitability and blast radius."""


SYSTEM_COMPARISON = """\
You are an expert multi-cloud IAM architect comparing \
identity policies across AWS IAM, GCP IAM, and Azure \
RBAC.

Given policies from multiple cloud providers:
1. Identify inconsistencies in permission models across \
providers
2. Detect gaps where one provider is hardened but \
others are not
3. Recommend cross-cloud alignment strategies
4. Score overall consistency for governance reporting

Account for fundamental differences in IAM models \
while identifying actionable alignment gaps."""


SYSTEM_REPORT = """\
You are an expert IAM governance reporter synthesizing \
cross-cloud identity analysis results.

Given the full IAM analysis pipeline output:
1. Produce an executive summary of IAM risk posture
2. Highlight critical findings requiring immediate \
remediation
3. Map findings to compliance framework requirements
4. Recommend a prioritized optimization roadmap

Write for CISO, compliance, and platform engineering \
audiences."""
