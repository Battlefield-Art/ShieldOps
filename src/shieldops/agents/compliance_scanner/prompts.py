"""Compliance Scanner Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class FindingEvaluationResult(BaseModel):
    """Structured output from LLM-assisted finding evaluation."""

    summary: str = Field(description="Summary of compliance findings")
    critical_gaps: list[str] = Field(description="Critical compliance gaps identified")
    risk_areas: list[str] = Field(description="Risk areas requiring immediate attention")
    remediation_priorities: list[str] = Field(description="Prioritized remediation actions")


class EvidenceGenerationResult(BaseModel):
    """Structured output for evidence generation guidance."""

    summary: str = Field(description="Summary of evidence collection")
    evidence_gaps: list[str] = Field(description="Controls lacking sufficient evidence")
    collection_recommendations: list[str] = Field(
        description="Recommendations for evidence collection"
    )
    automation_opportunities: list[str] = Field(
        description="Evidence collection that can be automated"
    )


class ComplianceReportResult(BaseModel):
    """Structured output for compliance report."""

    executive_summary: str = Field(description="Executive summary")
    compliance_posture: str = Field(description="Overall compliance posture assessment")
    framework_scores: list[str] = Field(description="Compliance score per framework")
    action_items: list[str] = Field(description="Prioritized action items")


SYSTEM_EVALUATE = (
    "You are a compliance auditor evaluating scan findings.\n"
    "For the compliance findings:\n"
    "1. Identify critical compliance gaps that pose regulatory risk\n"
    "2. Assess risk areas based on framework requirements\n"
    "3. Prioritize remediation actions by regulatory impact\n"
    "4. Determine which findings indicate systemic control weaknesses"
)

SYSTEM_EVIDENCE = (
    "You are a compliance evidence specialist.\n"
    "For the compliance controls:\n"
    "1. Identify controls lacking sufficient evidence\n"
    "2. Recommend appropriate evidence types for each control\n"
    "3. Identify evidence collection that can be automated\n"
    "4. Ensure evidence meets audit-quality standards"
)

SYSTEM_REPORT = (
    "You are a compliance officer generating an audit-ready report.\n"
    "Generate a comprehensive compliance report:\n"
    "1. Executive summary of compliance posture across all frameworks\n"
    "2. Framework-specific compliance scores and gap analysis\n"
    "3. Prioritized action items for compliance improvement\n"
    "4. Evidence readiness assessment for upcoming audits"
)
