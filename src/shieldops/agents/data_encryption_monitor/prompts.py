"""Data Encryption Monitor Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class EncryptionAssessmentResult(BaseModel):
    """Structured output from LLM encryption assessment."""

    summary: str = Field(description="Brief summary of encryption posture assessment")
    unencrypted_count: int = Field(description="Number of unencrypted assets found")
    weak_algorithm_count: int = Field(description="Number of assets using weak encryption")
    risk_level: str = Field(description="Overall risk: low, medium, high, critical")
    priority_recommendations: list[str] = Field(description="Top recommendations ranked by risk")


class KeyRotationAnalysisResult(BaseModel):
    """Structured output from LLM key rotation analysis."""

    summary: str = Field(description="Brief summary of key rotation health")
    overdue_keys: int = Field(description="Number of keys past rotation deadline")
    compliance_gaps: list[str] = Field(
        description="Compliance frameworks impacted by rotation gaps"
    )
    remediation_steps: list[str] = Field(description="Steps to remediate key rotation issues")


class EncryptionReportResult(BaseModel):
    """Structured output from LLM encryption report generation."""

    executive_summary: str = Field(description="Executive summary of encryption posture")
    coverage_assessment: str = Field(
        description="Assessment of encryption coverage: strong, adequate, weak"
    )
    top_risks: list[str] = Field(description="Top encryption risks identified")
    compliance_impact: str = Field(description="Impact on regulatory compliance")
    maturity_score: float = Field(description="Encryption maturity score from 0.0 to 1.0")


SYSTEM_ENCRYPTION_ASSESSMENT = (
    "You are an encryption security analyst for an AI security "
    "control plane.\n"
    "Analyze the following data store encryption posture:\n"
    "1. Identify unencrypted data stores holding sensitive data\n"
    "2. Flag weak encryption algorithms (DES, 3DES, RC4, MD5)\n"
    "3. Assess encryption-at-rest and in-transit coverage\n"
    "4. Map findings to compliance requirements (HIPAA, PCI DSS, "
    "SOC 2, GDPR)\n"
    "5. Prioritize remediation by data sensitivity and exposure"
)

SYSTEM_KEY_ROTATION = (
    "You are a cryptographic key management specialist.\n"
    "Given the key rotation status across cloud providers:\n"
    "1. Identify keys that are overdue for rotation\n"
    "2. Assess auto-rotation coverage gaps\n"
    "3. Evaluate key usage patterns for anomalies\n"
    "4. Check compliance with key rotation policies "
    "(NIST 800-57, PCI DSS 3.6)\n"
    "5. Recommend rotation schedule improvements"
)

SYSTEM_ENCRYPTION_REPORT = (
    "You are a CISO generating an encryption posture report "
    "for an enterprise.\n"
    "Given the complete encryption assessment results:\n"
    "1. Produce an executive summary covering encryption at "
    "rest, in transit, and key management\n"
    "2. Highlight certificate health risks (expiring, expired, "
    "self-signed)\n"
    "3. Assess regulatory impact (HIPAA requires AES-256, "
    "PCI DSS requires TLS 1.2+)\n"
    "4. Provide risk-ranked recommendations\n"
    "5. Score overall encryption maturity (0.0 to 1.0)"
)
