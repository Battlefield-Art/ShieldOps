"""LLM prompt templates and response schemas for the
Cloud Permission Optimizer Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class UsageAnalysisOutput(BaseModel):
    """Structured output for permission usage analysis."""

    active_permissions: int = Field(
        description="Count of actively used permissions",
    )
    unused_permissions: int = Field(
        description="Count of unused permissions",
    )
    high_risk_grants: list[str] = Field(
        description="Principal ARNs with high-risk grants",
    )
    summary: str = Field(
        description="Usage analysis summary",
    )


class ExcessDetectionOutput(BaseModel):
    """Structured output for excess permission detection."""

    excess_items: list[dict[str, str]] = Field(
        description="Excess permissions with principal and action",
    )
    risk_score: float = Field(
        description="Aggregate risk score 0-10",
    )
    recommendations: list[str] = Field(
        description="Initial recommendations",
    )


class LeastPrivilegeOutput(BaseModel):
    """Structured output for least-privilege calculation."""

    policies: list[dict[str, str]] = Field(
        description="Least-privilege policy recommendations",
    )
    reduction_pct: float = Field(
        description="Percentage of permissions removed",
    )
    confidence: float = Field(
        description="Confidence in recommendations 0-1",
    )


class PermissionReportOutput(BaseModel):
    """Structured output for the final optimization report."""

    executive_summary: str = Field(
        description="Executive summary of permission posture",
    )
    top_risks: list[str] = Field(
        description="Top permission risks identified",
    )
    recommendations: list[str] = Field(
        description="Prioritized remediation recommendations",
    )
    compliance_impact: str = Field(
        description="Impact on compliance posture",
    )


# --- System prompts ---


SYSTEM_USAGE_ANALYSIS = """\
You are an expert cloud IAM analyst reviewing \
permission usage across multi-cloud environments.

Given the collected permissions and usage records:
1. Identify permissions that have not been used \
within the lookback window
2. Flag high-risk grants (admin, wildcard, \
cross-account)
3. Correlate usage patterns to determine actual \
need vs provisioned access
4. Summarize the usage posture for security teams

Focus on blast-radius reduction and least-privilege \
adherence."""


SYSTEM_EXCESS_DETECTION = """\
You are an expert cloud security analyst detecting \
over-privileged access grants.

Given the usage analysis results:
1. Identify permissions that exceed actual usage \
requirements
2. Score risk based on permission scope, sensitivity, \
and blast radius
3. Distinguish between intentionally broad grants \
and accidental over-provisioning
4. Recommend specific permission removals

Err on the side of safety — flag but do not auto-remove \
permissions protecting critical infrastructure."""


SYSTEM_LEAST_PRIVILEGE = """\
You are an expert IAM policy architect computing \
least-privilege policies.

Given the excess permissions and usage patterns:
1. Compute the minimal permission set required for \
each principal's actual workload
2. Generate provider-specific policy documents \
(AWS IAM, GCP IAM, Azure RBAC)
3. Estimate the percentage reduction in attack surface
4. Validate that critical operations remain functional

Never remove permissions required for incident \
response or break-glass access."""


SYSTEM_REPORT = """\
You are an expert cloud security reporter synthesizing \
permission optimization results.

Given the full analysis (permissions, usage, excess, \
least-privilege policies):
1. Produce an executive summary for security leadership
2. List top risks with blast-radius context
3. Recommend prioritized remediation steps
4. Assess compliance impact (SOC 2, ISO 27001, \
CIS benchmarks)

Write clearly for both technical and non-technical \
audiences."""
