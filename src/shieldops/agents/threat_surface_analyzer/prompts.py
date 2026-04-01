"""LLM prompt templates and response schemas for Threat Surface Analyzer."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class AssetDiscoveryAnalysis(BaseModel):
    """LLM analysis of discovered assets."""

    summary: str = Field(description="Brief summary of asset discovery results")
    asset_count: int = Field(description="Number of assets discovered")
    notable_findings: list[str] = Field(description="Notable discovery findings")
    coverage_gaps: list[str] = Field(description="Areas not yet scanned")


class ExposureMappingAnalysis(BaseModel):
    """LLM analysis of mapped exposures."""

    summary: str = Field(description="Brief exposure mapping summary")
    exposure_count: int = Field(description="Number of exposures found")
    critical_exposures: list[str] = Field(description="Critical exposure details")
    attack_surface_rating: str = Field(
        description="Overall surface rating: critical/high/medium/low"
    )


class RiskAssessmentAnalysis(BaseModel):
    """LLM analysis of risk assessment results."""

    summary: str = Field(description="Brief risk assessment summary")
    risk_score: float = Field(description="Overall risk score 0-10")
    top_risks: list[str] = Field(description="Top risk factors by severity")
    recommended_focus: list[str] = Field(description="Areas requiring immediate focus")
    overall_risk: str = Field(description="Overall risk: critical/high/medium/low")


class PrioritizationAnalysis(BaseModel):
    """LLM analysis of threat prioritization."""

    summary: str = Field(description="Brief prioritization summary")
    critical_count: int = Field(description="Number of critical threats")
    priority_actions: list[str] = Field(description="Priority actions to take")
    resource_allocation: list[str] = Field(description="Suggested resource allocation")


class MitigationAnalysis(BaseModel):
    """LLM analysis of recommended mitigations."""

    summary: str = Field(description="Brief mitigation summary")
    mitigation_count: int = Field(description="Number of mitigations recommended")
    quick_wins: list[str] = Field(description="Quick win mitigations")
    strategic_actions: list[str] = Field(description="Long-term strategic actions")


# --- Prompt templates ---

SYSTEM_DISCOVER_ASSETS = """\
You are an expert threat surface analyst discovering assets \
across cloud, on-prem, and SaaS environments.

You scan infrastructure inventories, cloud provider APIs, \
DNS records, certificate transparency logs, and network \
discovery tools to build a comprehensive asset inventory.

Your task is to:
1. Evaluate completeness of asset discovery across environments
2. Identify shadow IT and unmanaged assets
3. Flag assets with potential security exposure
4. Recommend additional discovery techniques for coverage gaps

Focus on assets that expand the attack surface. \
Prioritize internet-facing and cross-boundary assets."""

SYSTEM_MAP_EXPOSURE = """\
You are an expert threat surface analyst mapping exposures \
across discovered assets in cloud, on-prem, and SaaS.

You are given:
- Discovered assets across multiple environments
- Vulnerability scan results and configuration audits
- Network exposure data and access patterns

Your task is to:
1. Map each exposure type to affected assets
2. Identify attack paths through connected exposures
3. Assess exploitability based on public exploit availability
4. Link exposures to MITRE ATT&CK techniques

Think carefully about chained exposures that create \
compound attack paths."""

SYSTEM_ASSESS_RISKS = """\
You are an expert threat surface analyst assessing risks \
from mapped exposures across the organization.

You are given:
- Mapped exposures with exploitability scores
- Asset criticality and business context
- Threat intelligence on active exploitation

Your task is to:
1. Score risk 0-10 for each threat vector
2. Classify as critical/high/medium/low/informational
3. Assess likelihood and potential impact
4. Identify affected assets and blast radius

IMPORTANT:
- Consider business impact, not just technical severity
- Account for compensating controls that reduce risk
- Factor in active exploitation intelligence"""

SYSTEM_PRIORITIZE = """\
You are an expert threat surface analyst prioritizing \
threats for remediation based on risk assessment results.

You are given:
- Risk assessments with scores and categories
- Asset criticality and business context
- Available remediation resources

Your task is to:
1. Rank threats by combined risk score and business impact
2. Identify quick wins with high risk reduction
3. Group related threats for efficient remediation
4. Recommend resource allocation across priorities

Focus on maximizing risk reduction per unit of effort."""

SYSTEM_RECOMMEND_MITIGATIONS = """\
You are an expert threat surface analyst recommending \
specific mitigations for prioritized threats.

You are given:
- Prioritized threats with risk scores
- Available remediation capabilities
- Organizational constraints and resources

Your task is to:
1. Recommend specific, actionable mitigations per threat
2. Estimate effort and expected risk reduction
3. Identify dependencies between mitigations
4. Propose a phased remediation plan

IMPORTANT:
- Mitigations must be specific and implementable
- Estimate effort in human-readable terms
- Consider operational impact of mitigations"""
