"""Crypto Agility Manager Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class AgilityAnalysisResult(BaseModel):
    """Structured output from LLM-assisted agility assessment."""

    summary: str = Field(description="Summary of cryptographic agility posture")
    critical_services: list[str] = Field(
        description="Services with quantum-vulnerable algorithms requiring immediate action"
    )
    risk_assessment: str = Field(
        description="Overall risk assessment of cryptographic posture against quantum threats"
    )
    recommendations: list[str] = Field(description="Prioritized recommendations for PQC migration")


class MigrationPlanResult(BaseModel):
    """Structured output for PQC migration planning."""

    summary: str = Field(description="Summary of PQC migration plan")
    migration_order: list[str] = Field(description="Recommended order for algorithm migrations")
    risks: list[str] = Field(description="Risks associated with the migration plan")
    hybrid_strategy: str = Field(description="Recommended hybrid classical+PQC transition strategy")
    rollback_steps: list[str] = Field(description="Steps to rollback if migration causes issues")


class CryptoReportResult(BaseModel):
    """Structured output for crypto agility management report."""

    executive_summary: str = Field(description="Executive summary")
    compliance_status: str = Field(
        description="Compliance status against NIST PQC standards and CNSA 2.0 timeline"
    )
    action_items: list[str] = Field(description="Action items for the security team")
    improvements: list[str] = Field(description="Strategic improvements for cryptographic agility")


SYSTEM_ANALYZE = (
    "You are a post-quantum cryptography expert analyzing an organization's "
    "cryptographic algorithm inventory.\n"
    "For the discovered algorithms:\n"
    "1. Identify quantum-vulnerable algorithms (RSA, ECDSA, DH, ECDH) and classify risk\n"
    "2. Assess cryptographic agility — can services negotiate or swap algorithms?\n"
    "3. Prioritize services for PQC migration based on data sensitivity and exposure\n"
    "4. Recommend NIST-approved PQC replacements: CRYSTALS-Kyber (KEM), "
    "CRYSTALS-Dilithium (signatures), SPHINCS+ (hash-based signatures)\n"
    "5. Consider hybrid mode (classical + PQC) as a transition strategy\n"
    "6. Flag any use of deprecated or weak algorithms (MD5, SHA-1, DES, 3DES, RC4)"
)

SYSTEM_REPORT = (
    "You are a cryptographic compliance officer reviewing post-quantum readiness.\n"
    "Generate a comprehensive report:\n"
    "1. Executive summary of cryptographic inventory health and quantum risk\n"
    "2. Compliance status against NIST PQC standards, CNSA 2.0 timeline, "
    "and CISA quantum-readiness guidance\n"
    "3. Action items ranked by priority (critical quantum-vulnerable services first)\n"
    "4. Strategic roadmap for achieving full cryptographic agility\n"
    "5. Hybrid deployment recommendations for zero-downtime migration"
)
