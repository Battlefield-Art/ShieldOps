"""Data Classification Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class SensitivityAnalysisResult(BaseModel):
    """Structured output from LLM-assisted sensitivity analysis."""

    summary: str = Field(description="Brief summary of data sensitivity findings")
    total_findings: int = Field(description="Total number of sensitive data findings")
    highest_sensitivity: str = Field(
        description="Highest sensitivity level found: top_secret, confidential, "
        "internal, public, unclassified"
    )
    category_breakdown: list[str] = Field(description="Breakdown of findings by data category")
    recommended_actions: list[str] = Field(description="Recommended actions for data protection")


class RegulatoryGapResult(BaseModel):
    """Structured output from LLM-assisted regulatory gap analysis."""

    summary: str = Field(description="Brief summary of regulatory compliance gaps")
    gap_count: int = Field(description="Number of compliance gaps identified")
    critical_gaps: list[str] = Field(
        description="Critical compliance gaps requiring immediate action"
    )
    remediation_steps: list[str] = Field(description="Ordered remediation steps to close gaps")
    risk_level: str = Field(description="Overall regulatory risk: low, medium, high, critical")


class ClassificationReportResult(BaseModel):
    """Structured output from LLM-assisted classification report generation."""

    executive_summary: str = Field(
        description="Executive summary of the data classification assessment"
    )
    risk_posture: str = Field(
        description="Overall data risk posture: strong, adequate, weak, critical"
    )
    top_risks: list[str] = Field(description="Top data-related risks identified")
    dlp_recommendations: list[str] = Field(description="Data Loss Prevention recommendations")
    compliance_score: float = Field(description="Compliance score from 0.0 to 1.0")


SYSTEM_SENSITIVITY_ANALYSIS = (
    "You are a data security analyst specializing in data classification.\n"
    "Analyze the following data assets and sensitive data findings.\n"
    "For each finding:\n"
    "1. Validate the sensitivity level assignment based on data category\n"
    "2. Identify any misclassified or under-classified data\n"
    "3. Flag assets with multiple sensitive data categories (compound risk)\n"
    "4. Assess confidence levels and recommend deeper scanning where low\n"
    "5. Prioritize findings by risk to the organization"
)

SYSTEM_REGULATORY_GAP = (
    "You are a compliance analyst specializing in data protection regulations.\n"
    "Based on the sensitive data findings and regulatory mappings:\n"
    "1. Identify compliance gaps where sensitive data lacks required controls\n"
    "2. Map gaps to specific regulatory articles/requirements\n"
    "3. Prioritize gaps by regulatory penalty risk (GDPR fines, HIPAA penalties)\n"
    "4. Recommend specific technical and procedural remediation steps\n"
    "5. Estimate time and effort for each remediation item"
)

SYSTEM_CLASSIFICATION_REPORT = (
    "You are a chief data officer generating a data classification report.\n"
    "Given the complete classification results:\n"
    "1. Produce an executive summary suitable for board-level reporting\n"
    "2. Assess the overall data risk posture of the organization\n"
    "3. Identify the top data-related risks and their business impact\n"
    "4. Recommend DLP controls (encryption, masking, access controls, monitoring)\n"
    "5. Provide a compliance readiness score with supporting evidence"
)
