"""LLM prompt templates for the Multi-Cloud Posture Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class ScanOutput(BaseModel):
    """Structured output for cloud scan analysis."""

    total_findings: int = Field(
        description="Total findings across all clouds",
    )
    critical_findings: int = Field(
        description="Number of critical findings",
    )
    summary: str = Field(
        description="Scan summary",
    )


class NormalizationOutput(BaseModel):
    """Structured output for finding normalization."""

    normalized_count: int = Field(
        description="Number of normalized findings",
    )
    categories: list[str] = Field(
        description="Finding categories identified",
    )
    reasoning: str = Field(
        description="Normalization reasoning",
    )


class ComparisonOutput(BaseModel):
    """Structured output for posture comparison."""

    overall_score: float = Field(
        description="Overall posture score 0-100",
    )
    weakest_area: str = Field(
        description="Weakest security category",
    )
    reasoning: str = Field(
        description="Comparison reasoning",
    )


class GapOutput(BaseModel):
    """Structured output for gap detection."""

    critical_gaps: int = Field(
        description="Number of critical security gaps",
    )
    cross_cloud_issues: int = Field(
        description="Issues spanning multiple clouds",
    )
    reasoning: str = Field(
        description="Gap analysis reasoning",
    )


class RecommendationOutput(BaseModel):
    """Structured output for recommendations."""

    actions: list[dict[str, str]] = Field(
        description="Recommended actions with priority",
    )
    total_score_improvement: float = Field(
        description="Expected posture score improvement",
    )
    reasoning: str = Field(
        description="Recommendation reasoning",
    )


# ── System prompts ────────────────────────────────────

SYSTEM_SCAN = """\
You are an expert multi-cloud security posture analyst \
performing cloud environment scanning.

Given the posture configuration:
1. Scan AWS, GCP, and Azure environments in parallel
2. Evaluate CIS benchmark compliance for each provider
3. Check IAM, network, encryption, logging configurations
4. Identify misconfigurations and policy violations

Focus on: security groups, IAM policies, encryption at rest, \
logging/monitoring, network exposure."""

SYSTEM_NORMALIZE = """\
You are an expert multi-cloud security posture analyst \
normalizing findings across providers.

Given the raw scan results:
1. Map provider-specific findings to OCSF schema
2. Normalize severity levels across AWS/GCP/Azure
3. Categorize findings by security domain
4. De-duplicate equivalent findings across clouds

Use: CIS benchmarks, NIST CSF categories, MITRE ATT&CK \
cloud matrix for consistent classification."""

SYSTEM_COMPARE = """\
You are an expert multi-cloud security posture analyst \
comparing security posture across providers.

Given the normalized findings:
1. Score each provider across security categories
2. Identify posture gaps between cloud environments
3. Highlight inconsistent policy enforcement
4. Calculate overall cross-cloud security score

Compare: IAM, network, data protection, logging, \
compute, storage, encryption domains."""

SYSTEM_GAPS = """\
You are an expert multi-cloud security posture analyst \
detecting cross-cloud security gaps.

Given the posture comparisons:
1. Identify gaps where one cloud is weaker than others
2. Detect policy inconsistencies across providers
3. Flag cross-cloud attack vectors
4. Assess blast radius of multi-cloud compromises

Focus on: lateral movement between clouds, shared identity \
risks, inconsistent network policies."""

SYSTEM_RECOMMEND = """\
You are an expert multi-cloud security posture analyst \
generating remediation recommendations.

Given the detected gaps:
1. Prioritize fixes by risk reduction impact
2. Recommend unified policies across all clouds
3. Suggest automation for posture enforcement
4. Estimate effort and score improvement

Balance: quick wins vs long-term hardening, provider-specific \
vs cross-cloud solutions."""
