"""Sensitive Data Monitor Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class SensitiveDataAnalysisResult(BaseModel):
    """LLM output for sensitive data scan analysis."""

    summary: str = Field(description="Brief summary of sensitive data findings")
    total_hits: int = Field(description="Total sensitive data hits detected")
    highest_risk_category: str = Field(description="Category with highest risk exposure")
    ai_pipeline_risks: list[str] = Field(description="Risks specific to AI pipeline data")
    recommended_actions: list[str] = Field(description="Prioritized remediation actions")


class ExposureAnalysisResult(BaseModel):
    """LLM output for exposure risk assessment."""

    summary: str = Field(description="Brief summary of exposure assessment")
    critical_exposures: int = Field(description="Number of critical exposure findings")
    public_data_risks: list[str] = Field(description="Data exposed to public access")
    remediation_priority: list[str] = Field(description="Ordered remediation priorities")
    risk_level: str = Field(description="Overall risk: low, medium, high, critical")


class MonitorReportResult(BaseModel):
    """LLM output for the final monitoring report."""

    executive_summary: str = Field(description="Executive summary of monitoring run")
    risk_posture: str = Field(description="Posture: strong, adequate, weak, critical")
    top_risks: list[str] = Field(description="Top data exposure risks identified")
    compliance_gaps: list[str] = Field(description="Regulatory compliance gaps found")
    dlp_recommendations: list[str] = Field(description="Data loss prevention recommendations")
    compliance_score: float = Field(description="Compliance score from 0.0 to 1.0")


SYSTEM_SENSITIVE_DATA_ANALYSIS = (
    "You are a data security analyst specializing in "
    "sensitive data monitoring and classification.\n"
    "Analyze the detected sensitive data findings:\n"
    "1. Validate classification accuracy for each hit\n"
    "2. Identify AI pipeline-specific risks (prompts, "
    "RAG data, training data leakage)\n"
    "3. Flag data with multiple category overlap\n"
    "4. Assess detection confidence and recommend "
    "deeper scanning where confidence is low\n"
    "5. Prioritize by organizational risk impact"
)

SYSTEM_EXPOSURE_ANALYSIS = (
    "You are a data exposure analyst assessing risk.\n"
    "Based on the classified sensitive data and exposure "
    "assessments:\n"
    "1. Identify publicly accessible sensitive data\n"
    "2. Assess encryption gaps (at-rest and in-transit)\n"
    "3. Evaluate access principal counts vs least "
    "privilege principles\n"
    "4. Map exposures to regulatory requirements "
    "(GDPR Art. 30, HIPAA, PCI DSS 3.4)\n"
    "5. Recommend specific technical controls to reduce "
    "exposure risk"
)

SYSTEM_MONITOR_REPORT = (
    "You are a chief data protection officer generating "
    "a sensitive data monitoring report.\n"
    "Given complete monitoring results:\n"
    "1. Produce an executive summary for board reporting\n"
    "2. Assess overall data risk posture including AI "
    "pipeline data flows\n"
    "3. Identify top risks with business impact\n"
    "4. Map compliance gaps to GDPR, HIPAA, PCI DSS\n"
    "5. Recommend DLP controls: encryption, masking, "
    "access controls, AI guardrails\n"
    "6. Provide compliance readiness score"
)
