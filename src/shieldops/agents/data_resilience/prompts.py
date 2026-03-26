"""Data Resilience Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class InventoryAnalysisResult(BaseModel):
    """Structured output from LLM-assisted inventory."""

    summary: str = Field(description="Brief summary of discovered data assets")
    high_value_assets: list[str] = Field(description="Assets requiring immediate protection")
    coverage_gaps: list[str] = Field(description="Areas with missing or incomplete inventory")


class ProtectionInsight(BaseModel):
    """Structured output from LLM-assisted protection assessment."""

    summary: str = Field(description="Brief protection posture overview")
    critical_gaps: list[str] = Field(description="Protection gaps requiring urgent action")
    compliance_risks: list[str] = Field(description="Compliance risks from protection gaps")


class AnomalyAssessment(BaseModel):
    """Structured output from LLM-assisted anomaly detection."""

    summary: str = Field(description="Anomaly detection overview")
    ransomware_indicators: list[str] = Field(
        description="Indicators suggesting ransomware activity"
    )
    recommended_actions: list[str] = Field(description="Recommended response actions")


class EnforcementReview(BaseModel):
    """Structured output from LLM-assisted enforcement review."""

    summary: str = Field(description="Enforcement action overview")
    priority_assets: list[str] = Field(description="Assets needing priority enforcement")
    configuration_notes: list[str] = Field(description="Configuration recommendations")


class RecoveryInsight(BaseModel):
    """Structured output from LLM-assisted recovery validation."""

    summary: str = Field(description="Recovery readiness overview")
    failures: list[str] = Field(description="Recovery tests that failed or degraded")
    improvements: list[str] = Field(description="Suggested recovery improvements")


SYSTEM_INVENTORY = (
    "You are a data resilience engineer inventorying"
    " data assets across multi-cloud and AI pipelines.\n"
    "For the discovered assets:\n"
    "1. Identify high-value assets (AI models, RAG"
    " indexes, training data, production databases)\n"
    "2. Flag assets without classification or ownership\n"
    "3. Note coverage gaps in the inventory\n"
    "4. Prioritise assets by business criticality"
)

SYSTEM_PROTECTION = (
    "You are a data protection specialist assessing"
    " resilience posture.\n"
    "For each protection assessment:\n"
    "1. Evaluate immutability controls (object lock,"
    " WORM, versioning)\n"
    "2. Assess backup recency and replication status\n"
    "3. Identify compliance gaps (HIPAA, SOC2, PCI)\n"
    "4. Score overall protection level and recommend"
    " upgrades"
)

SYSTEM_ANOMALY = (
    "You are a ransomware detection analyst examining"
    " data anomalies.\n"
    "For each anomaly:\n"
    "1. Evaluate whether patterns match ransomware"
    " behaviour (mass encryption, rapid deletion)\n"
    "2. Check for data exfiltration indicators\n"
    "3. Assess tampering risk on AI model weights"
    " and training data\n"
    "4. Recommend containment actions for confirmed"
    " threats"
)

SYSTEM_ENFORCEMENT = (
    "You are a storage security engineer enforcing"
    " immutability controls.\n"
    "For each enforcement action:\n"
    "1. Recommend appropriate lock mechanism"
    " (S3 Object Lock, Azure Immutable Blob,"
    " GCS Retention)\n"
    "2. Set retention periods based on compliance"
    " requirements\n"
    "3. Ensure rollback capabilities remain available\n"
    "4. Verify encryption is applied alongside locks"
)

SYSTEM_RECOVERY = (
    "You are a disaster recovery engineer validating"
    " recovery capabilities.\n"
    "For each recovery test:\n"
    "1. Evaluate RTO/RPO against SLA requirements\n"
    "2. Verify data integrity via checksum validation\n"
    "3. Identify single points of failure in recovery"
    " paths\n"
    "4. Recommend improvements to reduce recovery time"
)
