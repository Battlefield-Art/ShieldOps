"""Compliance Reporter Agent — LLM prompt templates and output schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Output schemas for LLM structured calls
# ---------------------------------------------------------------------------


class EvidenceAnalysisOutput(BaseModel):
    """LLM-generated analysis of collected evidence quality and coverage."""

    coverage_assessment: str = Field(
        description="Overall assessment of evidence coverage across controls"
    )
    gaps: list[str] = Field(description="Controls lacking sufficient evidence")
    stale_artifacts: list[str] = Field(
        description="Evidence items that may be outdated or require refresh"
    )
    confidence: float = Field(description="Confidence score (0-1) in evidence completeness")


class ControlAssessmentOutput(BaseModel):
    """LLM-generated control assessment reasoning."""

    compliant_controls: list[str] = Field(description="Control IDs that fully meet requirements")
    non_compliant_controls: list[str] = Field(
        description="Control IDs that fail to meet requirements"
    )
    critical_findings: list[str] = Field(
        description="Most critical compliance findings requiring action"
    )
    risk_level: str = Field(description="Overall risk level: critical, high, medium, or low")
    assessment_rationale: str = Field(description="Rationale for the overall compliance assessment")


class ReportNarrativeOutput(BaseModel):
    """LLM-generated executive summary and narrative for the compliance report."""

    executive_summary: str = Field(
        description="Executive summary suitable for C-level stakeholders"
    )
    key_strengths: list[str] = Field(description="Areas where compliance posture is strong")
    key_risks: list[str] = Field(description="Areas of highest compliance risk")
    recommendations: list[str] = Field(
        description="Prioritized recommendations for compliance improvement"
    )


class RemediationOutput(BaseModel):
    """LLM-generated remediation plan for non-compliant controls."""

    remediation_plan: list[str] = Field(
        description="Ordered remediation steps across all non-compliant controls"
    )
    estimated_effort: str = Field(
        description="Estimated effort to remediate all findings (low/medium/high)"
    )
    quick_wins: list[str] = Field(
        description="Low-effort fixes that significantly improve compliance posture"
    )
    timeline_weeks: int = Field(description="Estimated weeks to achieve full remediation")


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_EVIDENCE_ANALYSIS = (
    "You are a compliance evidence analyst for an AI security control plane.\n"
    "Evaluate the collected evidence artifacts for completeness and quality.\n"
    "For each control:\n"
    "1. Verify evidence is current (within 90-day freshness window)\n"
    "2. Check evidence type matches control requirements\n"
    "3. Identify gaps where evidence is missing or insufficient\n"
    "4. Assess whether automated collection covers the control adequately\n"
    "5. Flag any evidence that needs manual verification"
)

SYSTEM_CONTROL_ASSESSMENT = (
    "You are a senior compliance assessor evaluating controls against "
    "regulatory frameworks (SOC 2 Type II, PCI DSS 4.0, HIPAA, FedRAMP Moderate, "
    "GDPR, ISO 27001, NIST CSF).\n"
    "For each control:\n"
    "1. Evaluate whether the evidence demonstrates compliance\n"
    "2. Identify specific deficiencies for non-compliant controls\n"
    "3. Assess risk severity of each finding\n"
    "4. Provide clear, actionable remediation guidance\n"
    "5. Consider compensating controls where applicable"
)

SYSTEM_REPORT_GENERATION = (
    "You are generating an audit-ready compliance report for enterprise stakeholders.\n"
    "The report must be suitable for external auditors and C-level executives.\n"
    "Include:\n"
    "1. Executive summary with compliance score and risk posture\n"
    "2. Framework-specific scoring methodology explanation\n"
    "3. Strengths that demonstrate mature security practices\n"
    "4. Risks ranked by severity with business impact context\n"
    "5. Prioritized recommendations with estimated timelines\n"
    "6. Evidence references for each assessed control"
)

SYSTEM_REMEDIATION_PLANNING = (
    "You are a compliance remediation planner creating actionable fix plans.\n"
    "For each non-compliant or partially compliant control:\n"
    "1. Define specific remediation steps with clear owners\n"
    "2. Estimate effort (hours/days) per remediation item\n"
    "3. Identify quick wins that improve score with minimal effort\n"
    "4. Sequence remediation to address highest-risk items first\n"
    "5. Consider dependencies between controls for efficient fixes\n"
    "6. Provide an overall timeline to achieve target compliance score"
)
