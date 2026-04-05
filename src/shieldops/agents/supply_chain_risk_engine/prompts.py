"""LLM prompt templates and response schemas for Supply Chain Risk Engine."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class DependencyInventoryAnalysis(BaseModel):
    """LLM analysis of dependency inventory."""

    summary: str = Field(description="Brief inventory summary")
    dependency_count: int = Field(description="Dependencies found")
    types_found: list[str] = Field(description="Dependency types found")
    notable_findings: list[str] = Field(description="Notable findings")


class VulnerabilityScanAnalysis(BaseModel):
    """LLM analysis of vulnerability scan results."""

    summary: str = Field(description="Brief scan summary")
    vulnerability_count: int = Field(description="Vulnerabilities found")
    critical_cves: list[str] = Field(description="Critical CVEs found")
    scan_quality: str = Field(
        description="Quality: comprehensive/partial/limited",
    )


class RiskAssessmentAnalysis(BaseModel):
    """LLM analysis of risk assessments."""

    summary: str = Field(description="Brief risk assessment summary")
    high_risk_count: int = Field(description="High-risk dependencies")
    risk_drivers: list[str] = Field(description="Key risk drivers")
    risk_level: str = Field(
        description="Overall: critical/high/medium/low",
    )


class BlastRadiusAnalysis(BaseModel):
    """LLM analysis of blast radius mappings."""

    summary: str = Field(description="Brief blast radius summary")
    wide_blast_count: int = Field(
        description="Dependencies with wide blast radius",
    )
    affected_services: list[str] = Field(
        description="Most affected services",
    )
    containment_advice: str = Field(description="Containment advice")


class MitigationAnalysis(BaseModel):
    """LLM analysis of mitigation recommendations."""

    summary: str = Field(description="Brief mitigation summary")
    recommendation_count: int = Field(
        description="Recommendations generated",
    )
    quick_wins: list[str] = Field(description="Quick win fixes")
    automation_possible: bool = Field(
        description="Whether automation is feasible",
    )


# --- Prompt templates ---

SYSTEM_INVENTORY_DEPENDENCIES = """\
You are an expert software supply chain analyst inventorying \
dependencies across an enterprise codebase.

You examine package manifests, container images, OS packages, \
third-party API integrations, and build tool dependencies.

Your task is to:
1. Catalog all dependency types and their versions
2. Identify pinned vs floating version references
3. Flag unmaintained or deprecated dependencies
4. Assess completeness of the dependency inventory

Focus on transitive dependencies that may introduce hidden risk. \
Pay attention to dependencies with broad permissions."""

SYSTEM_SCAN_VULNERABILITIES = """\
You are an expert vulnerability analyst scanning software \
dependencies for known vulnerabilities.

You are given:
- Dependency inventory with version metadata
- CVE databases and advisory feeds
- CVSS scoring and exploitability data

Your task is to:
1. Match dependencies against known CVE records
2. Assess exploitability in the deployment context
3. Identify dependencies with available fixes
4. Prioritize vulnerabilities by severity and exploitability

IMPORTANT:
- CVSS score alone does not determine real-world risk
- Context matters: network-reachable vs internal-only
- Fix availability changes the urgency calculus"""

SYSTEM_ASSESS_RISK = """\
You are an expert supply chain risk analyst assessing \
aggregate risk across software dependencies.

You are given:
- Vulnerability scan results with severity ratings
- Dependency metadata (maintainer, update frequency)
- Historical incident data for supply chain attacks

Your task is to:
1. Calculate composite risk scores per dependency
2. Factor in maintainer reputation and update cadence
3. Identify correlated vulnerabilities that amplify risk
4. Classify risk levels for remediation prioritization

Consider typosquatting, dependency confusion, and \
compromised maintainer scenarios."""

SYSTEM_MAP_BLAST_RADIUS = """\
You are an expert supply chain analyst mapping the blast \
radius of vulnerable dependencies.

You are given:
- Risk-assessed dependencies with vulnerability data
- Service dependency graph and deployment topology
- Environment classification (prod/staging/dev)

Your task is to:
1. Trace downstream impact of each vulnerable dependency
2. Identify services and environments affected
3. Estimate cascading failure potential
4. Recommend containment boundaries

Wide blast radius dependencies require immediate attention. \
Production-facing dependencies take priority."""

SYSTEM_RECOMMEND_MITIGATIONS = """\
You are an expert supply chain security analyst recommending \
mitigations for supply chain risks.

You are given:
- Risk assessments with blast radius analysis
- Available patching and upgrade paths
- Organizational automation capabilities

Your task is to:
1. Propose specific mitigation actions per risk
2. Estimate effort and automation feasibility
3. Prioritize by risk impact and implementation cost
4. Group related mitigations for efficient execution

Quick wins (version bumps, pin updates) should be flagged \
for immediate action. Complex mitigations need phased plans."""
