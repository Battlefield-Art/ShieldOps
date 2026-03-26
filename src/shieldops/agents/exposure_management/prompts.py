"""LLM prompt templates and response schemas for Exposure Management."""

from pydantic import BaseModel, Field

# ── Structured Output Schemas ───────────────────────────────


class SurfaceDiscoveryOutput(BaseModel):
    """LLM output for attack surface discovery."""

    surfaces_found: int = Field(
        description="Number of attack surfaces discovered",
    )
    ai_surfaces: int = Field(
        description="Number of AI-specific surfaces found",
    )
    summary: str = Field(
        description="Summary of discovered surfaces",
    )
    risk_level: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


class ExposureAssessmentOutput(BaseModel):
    """LLM output for exposure assessment."""

    findings: list[dict[str, str]] = Field(
        description="Exposure findings with severity+description",
    )
    risk_score: float = Field(
        description="Composite risk score 0-100",
    )
    ai_risk_factors: list[str] = Field(
        description="AI-specific risk factors identified",
    )
    reasoning: str = Field(
        description="Assessment reasoning chain",
    )


class PrioritizationOutput(BaseModel):
    """LLM output for risk prioritization."""

    ranked_risks: list[dict[str, str]] = Field(
        description="Risks ranked by composite score",
    )
    top_risk_summary: str = Field(
        description="Summary of highest-priority risks",
    )
    reasoning: str = Field(
        description="Prioritization reasoning",
    )


class RemediationOutput(BaseModel):
    """LLM output for remediation recommendations."""

    actions: list[dict[str, str]] = Field(
        description="Remediation actions with priority+effort",
    )
    quick_wins: int = Field(
        description="Number of quick-win remediations",
    )
    automation_candidates: int = Field(
        description="Actions that can be automated",
    )
    reasoning: str = Field(
        description="Remediation reasoning",
    )


# ── System Prompts ──────────────────────────────────────────


SYSTEM_DISCOVER = """\
You are an expert attack surface analyst performing \
multi-surface discovery for an AI-enabled enterprise.

Given the tenant configuration and target scope:
1. Identify all attack surfaces: external network, cloud \
infrastructure, identity, AI endpoints, code repos, APIs
2. Flag AI-specific surfaces: exposed MCP servers, \
unprotected LLM endpoints, public RAG data stores
3. Classify each surface by type and initial risk level

Focus on continuous discovery, not point-in-time snapshots. \
Prioritize surfaces with internet-facing exposure."""


SYSTEM_ASSESS = """\
You are an expert exposure analyst assessing security \
exposures across multi-surface attack vectors.

Given discovered assets and their configurations:
1. Assess each exposure using CVSS and EPSS scoring
2. Check CISA KEV catalog for known exploited vulns
3. Map attack paths from exposure to blast radius
4. Identify AI-specific exposures: prompt injection \
surfaces, model theft vectors, data exfiltration paths

Weight AI endpoint exposures higher — they represent \
novel attack vectors that traditional tools miss."""


SYSTEM_PRIORITIZE = """\
You are an expert risk analyst prioritizing exposures \
using business-context-aware scoring.

Given assessed exposures with CVSS, EPSS, and KEV data:
1. Compute composite score: EPSS weight 0.3, CVSS 0.25, \
business impact 0.25, KEV 0.2
2. Factor attack path depth and blast radius
3. Assign remediation SLA based on composite score
4. Elevate AI-surface exposures due to novel risk profile

Produce a ranked list with clear remediation timelines."""


SYSTEM_REMEDIATE = """\
You are an expert remediation planner creating actionable \
fix recommendations for prioritized exposures.

Given prioritized risks with composite scores:
1. Recommend specific remediation actions per exposure
2. Identify quick wins (< 4 hours, high risk reduction)
3. Flag automation candidates for runbook integration
4. Estimate effort and dependencies

Balance speed with operational safety. Never recommend \
actions that exceed blast-radius limits."""


SYSTEM_REPORT = """\
You are an expert security analyst generating an exposure \
management report for executive and SOC audiences.

Given the full assessment results:
1. Summarize total exposure posture with trend indicators
2. Highlight critical and AI-specific exposures
3. Provide remediation progress and SLA compliance
4. Compare posture against industry benchmarks

Keep the report actionable with clear next steps."""
