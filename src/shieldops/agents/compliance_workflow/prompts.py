"""Compliance Workflow Agent — LLM prompt templates."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas for LLM calls ──────────


class LLMFrameworkAnalysis(BaseModel):
    """LLM output: framework applicability analysis."""

    applicable_frameworks: list[str] = Field(
        description=("Frameworks applicable to this tenant"),
    )
    rationale: str = Field(
        description="Why these frameworks apply",
    )


class LLMControlMapping(BaseModel):
    """LLM output: control mapping enrichment."""

    unmapped_risks: list[str] = Field(
        description=("Risks not covered by mapped controls"),
    )
    cross_framework_overlaps: list[str] = Field(
        description=("Controls shared across frameworks"),
    )
    mapping_confidence: float = Field(
        description=("Confidence in mapping completeness 0-1"),
    )


class LLMGapAssessment(BaseModel):
    """LLM output: compliance gap analysis."""

    critical_gaps: list[str] = Field(
        description=("Critical gaps needing immediate action"),
    )
    risk_summary: str = Field(
        description="Overall compliance risk summary",
    )
    estimated_effort: str = Field(
        description=("Remediation effort: low/medium/high"),
    )


class LLMRemediationPlan(BaseModel):
    """LLM output: remediation planning."""

    quick_wins: list[str] = Field(
        description=("Actions achievable within 1 week"),
    )
    strategic_actions: list[str] = Field(
        description=("Long-term remediation initiatives"),
    )
    risk_reduction_estimate: float = Field(
        description=("Expected risk reduction percentage"),
    )


class LLMComplianceReport(BaseModel):
    """LLM output: executive compliance report."""

    executive_summary: str = Field(
        description="2-3 sentence executive summary",
    )
    top_risks: list[str] = Field(
        description="Top 3 compliance risks",
    )
    recommended_timeline: str = Field(
        description=("Recommended remediation timeline"),
    )


# ── System prompts ────────────────────────────────────

SYSTEM_IDENTIFY_FRAMEWORKS = (
    "You are a compliance analyst identifying"
    " applicable regulatory frameworks for an"
    " organization.\n"
    "Consider industry, data types, geography,"
    " and customer requirements.\n"
    "Frameworks: SOC2, HIPAA, PCI-DSS, GDPR,"
    " ISO 27001, NIST CSF, FedRAMP.\n"
    "Return only frameworks with clear"
    " applicability."
)

SYSTEM_MAP_CONTROLS = (
    "You are mapping compliance controls across"
    " multiple regulatory frameworks.\n"
    "For each framework:\n"
    "1. Identify required controls and categories\n"
    "2. Find cross-framework overlaps to reduce"
    " duplicate effort\n"
    "3. Flag controls needing manual verification\n"
    "4. Prioritize controls protecting sensitive"
    " data"
)

SYSTEM_COLLECT_EVIDENCE = (
    "You are collecting evidence artifacts to"
    " support compliance control assessments.\n"
    "For each control:\n"
    "1. Gather config snapshots, logs, policies\n"
    "2. Verify freshness — reject artifacts"
    " older than 90 days\n"
    "3. Cross-reference across multiple sources\n"
    "4. Document chain of custody for each item"
)

SYSTEM_ASSESS_GAPS = (
    "You are performing gap analysis on"
    " compliance control assessments.\n"
    "For each non-compliant or partial control:\n"
    "1. Identify the unmet requirement\n"
    "2. Assess risk severity:"
    " critical/high/medium/low\n"
    "3. Determine root cause:"
    " policy, config, or process\n"
    "4. Estimate remediation effort and timeline"
)

SYSTEM_GENERATE_REMEDIATION = (
    "You are generating remediation actions for"
    " compliance gaps.\n"
    "For each gap:\n"
    "1. Define concrete remediation steps\n"
    "2. Estimate effort in days, assign priority\n"
    "3. Identify quick wins vs strategic items\n"
    "4. Consider cross-framework synergies"
)

SYSTEM_REPORT = (
    "You are generating an audit-ready compliance"
    " report.\n"
    "The report must include:\n"
    "1. Executive summary with compliance score\n"
    "2. Per-framework control status breakdown\n"
    "3. Gap analysis with prioritized remediation\n"
    "4. Risk exposure and timeline estimates\n"
    "5. Evidence coverage and freshness summary"
)
