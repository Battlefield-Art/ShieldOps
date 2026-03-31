"""LLM prompt templates and response schemas for the
Agentless Scanner Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class AssetDiscoveryOutput(BaseModel):
    """Structured output for asset discovery analysis."""

    asset_summary: list[dict[str, str]] = Field(
        description="Summary of discovered assets by type and region",
    )
    scan_priorities: list[str] = Field(
        description="Assets to prioritize for scanning",
    )
    coverage_gaps: list[str] = Field(
        description="Identified coverage gaps in discovery",
    )
    confidence: float = Field(
        description="Discovery completeness confidence 0-1",
    )


class ConfigAnalysisOutput(BaseModel):
    """Structured output for configuration analysis."""

    misconfigurations: int = Field(
        description="Number of misconfigurations found",
    )
    categories: list[str] = Field(
        description="Categories of config issues found",
    )
    risk_score: float = Field(
        description="Aggregate config risk score 0-10",
    )
    summary: str = Field(
        description="Configuration analysis summary",
    )


class ExposureAnalysisOutput(BaseModel):
    """Structured output for exposure analysis."""

    public_assets: int = Field(
        description="Number of publicly exposed assets",
    )
    attack_vectors: list[str] = Field(
        description="Identified attack vectors",
    )
    risk_score: float = Field(
        description="Exposure risk score 0-10",
    )
    recommendations: list[str] = Field(
        description="Remediation recommendations",
    )


class ScanReportOutput(BaseModel):
    """Structured output for final scan report."""

    executive_summary: str = Field(
        description="Executive summary of scan results",
    )
    critical_findings: int = Field(
        description="Number of critical findings",
    )
    recommendations: list[str] = Field(
        description="Top remediation recommendations",
    )
    compliance_status: str = Field(
        description="Overall compliance status",
    )
    risk_rating: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_DISCOVERY = """\
You are an expert cloud security scanner analyzing \
discovered cloud assets without deploying agents.

Given the target cloud providers, regions, and scope:
1. Categorize discovered assets by type and criticality
2. Identify assets requiring priority scanning
3. Flag coverage gaps in the discovery process
4. Assess completeness of the asset inventory

Focus on API-accessible resources: compute instances, \
storage buckets, databases, serverless functions, \
network configurations, and IAM entities."""


SYSTEM_CONFIG = """\
You are an expert cloud configuration auditor analyzing \
resource configurations via API snapshots.

Given the discovered assets and their configurations:
1. Identify misconfigurations against CIS benchmarks
2. Check for overly permissive access policies
3. Validate encryption-at-rest and in-transit settings
4. Assess network exposure and segmentation

Be specific about which benchmark control each finding \
violates and provide actionable remediation steps."""


SYSTEM_EXPOSURE = """\
You are an expert attack surface analyst assessing \
cloud asset exposure without deploying agents.

Given vulnerability and configuration findings:
1. Map internet-facing assets and their attack surface
2. Identify chained exposure paths across services
3. Score blast radius for each exposure vector
4. Recommend prioritized remediation actions

Consider lateral movement paths and privilege \
escalation chains across cloud boundaries."""


SYSTEM_REPORT = """\
You are an expert cloud security reporter synthesizing \
agentless scan results into actionable intelligence.

Given the full scan results (assets, configs, vulns, \
exposure analysis):
1. Produce an executive summary for security leadership
2. Highlight critical findings requiring immediate action
3. Provide compliance posture assessment
4. Recommend a prioritized remediation roadmap

Write clearly for both technical and executive audiences."""
