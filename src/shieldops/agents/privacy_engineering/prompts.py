"""Privacy Engineering Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class PrivacyAnalysisResult(BaseModel):
    """Structured output from LLM-assisted privacy analysis."""

    summary: str = Field(description="Brief summary of privacy engineering findings")
    total_findings: int = Field(description="Total number of privacy findings")
    highest_risk: str = Field(
        description="Highest risk level found: critical, high, medium, low, negligible"
    )
    technique_gaps: list[str] = Field(
        description="Privacy techniques that are missing or misconfigured"
    )
    recommended_actions: list[str] = Field(
        description="Recommended actions to strengthen privacy protections"
    )


class PrivacyReportResult(BaseModel):
    """Structured output from LLM-assisted privacy report generation."""

    executive_summary: str = Field(
        description="Executive summary of the privacy engineering assessment"
    )
    privacy_posture: str = Field(
        description="Overall privacy posture: strong, adequate, weak, critical"
    )
    top_risks: list[str] = Field(description="Top privacy risks identified")
    pet_recommendations: list[str] = Field(
        description="Privacy Enhancing Technology recommendations"
    )
    compliance_score: float = Field(description="Privacy compliance score from 0.0 to 1.0")


SYSTEM_ANALYZE = (
    "You are a privacy engineer specializing in data anonymization and "
    "Privacy Enhancing Technologies (PETs).\n"
    "Analyze the following data pipelines and privacy findings.\n"
    "For each finding:\n"
    "1. Evaluate the effectiveness of the anonymization technique used\n"
    "2. Assess differential privacy parameters (epsilon, delta) for utility/privacy tradeoff\n"
    "3. Identify re-identification risks from quasi-identifier combinations\n"
    "4. Validate PET implementations against best practices (OpenDP, Google DP, PySyft)\n"
    "5. Flag pipelines missing privacy-by-design controls\n"
    "6. Prioritize findings by re-identification risk and regulatory exposure"
)

SYSTEM_REPORT = (
    "You are a chief privacy officer generating a privacy engineering report.\n"
    "Given the complete privacy assessment results:\n"
    "1. Produce an executive summary suitable for DPO/board-level reporting\n"
    "2. Assess the overall privacy posture across all data pipelines\n"
    "3. Identify the top privacy risks and their regulatory impact\n"
    "4. Recommend PET upgrades (differential privacy tuning, k-anonymity improvements, "
    "homomorphic encryption adoption)\n"
    "5. Provide a privacy compliance readiness score with supporting evidence\n"
    "6. Map gaps to GDPR Art. 25 (data protection by design), CCPA, and HIPAA requirements"
)
