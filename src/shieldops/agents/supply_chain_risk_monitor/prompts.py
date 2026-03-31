"""LLM prompt templates and response schemas for the
Supply Chain Risk Monitor Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class DependencyAnalysisOutput(BaseModel):
    """Structured output for dependency analysis."""

    total_packages: int = Field(
        description="Total packages analyzed",
    )
    risk_indicators: list[str] = Field(
        description="Identified risk indicators",
    )
    typosquat_candidates: list[str] = Field(
        description="Suspected typosquatting packages",
    )
    confidence: float = Field(
        description="Overall analysis confidence 0-1",
    )


class RiskDetectionOutput(BaseModel):
    """Structured output for risk detection."""

    risks_found: int = Field(
        description="Number of risks detected",
    )
    categories: list[str] = Field(
        description="Risk categories identified",
    )
    severity_breakdown: dict[str, int] = Field(
        description="Count by severity level",
    )
    summary: str = Field(
        description="Risk detection summary",
    )


class ImpactAssessmentOutput(BaseModel):
    """Structured output for impact assessment."""

    blast_radius: int = Field(
        description="Number of affected services",
    )
    exploitability: float = Field(
        description="Exploitability score 0-1",
    )
    business_impact: str = Field(
        description="Business impact: critical/high/medium/low",
    )
    remediation_priority: list[str] = Field(
        description="Prioritized remediation steps",
    )


class SupplyChainReportOutput(BaseModel):
    """Structured output for supply chain report."""

    executive_summary: str = Field(
        description="Executive summary of supply chain posture",
    )
    slsa_compliance: str = Field(
        description="SLSA compliance status",
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations",
    )
    risk_trend: str = Field(
        description="Risk trend: improving/stable/degrading",
    )


# --- System prompts ---


SYSTEM_DEPENDENCIES = """\
You are an expert software supply chain analyst \
examining dependency trees for risk indicators.

Given the dependency scan results:
1. Identify packages with unusual naming patterns \
that suggest typosquatting
2. Flag dependencies with low maintainer trust scores
3. Detect dependency confusion attack vectors
4. Assess build provenance and SLSA compliance gaps

Focus on transitive dependencies which are the most \
common attack surface in supply chain compromises."""


SYSTEM_RISKS = """\
You are an expert supply chain security analyst \
detecting risks in software dependencies.

Given dependency analysis and vulnerability data:
1. Classify risks by category: typosquatting, \
maintainer risk, provenance, license, vulnerability
2. Score severity based on exploitability and blast radius
3. Correlate risks across the dependency graph
4. Distinguish real threats from noise

Prioritize risks that could lead to code execution \
in production environments."""


SYSTEM_IMPACT = """\
You are an expert risk assessor evaluating the \
business impact of supply chain vulnerabilities.

Given identified risks and the service dependency map:
1. Calculate blast radius for each vulnerability
2. Assess exploitability based on attack complexity
3. Map business impact to affected services
4. Recommend remediation priority based on risk score

Consider both direct and transitive impact paths \
through the dependency graph."""


SYSTEM_REPORT = """\
You are an expert supply chain security reporter \
synthesizing monitoring results.

Given the full supply chain risk assessment:
1. Produce an executive summary of supply chain posture
2. Report SLSA compliance status across repositories
3. List prioritized remediation recommendations
4. Assess risk trend over the monitoring period

Write for both engineering teams and security \
leadership."""
