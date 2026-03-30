"""Cloud Storage Scanner Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class PermissionInsight(BaseModel):
    """Structured output from permission scanning."""

    summary: str = Field(
        description="Brief permission scan overview",
    )
    critical_issues: list[str] = Field(
        description="Critical permission misconfigurations",
    )
    public_exposure_risks: list[str] = Field(
        description="Public exposure risk areas",
    )


class SensitiveDataInsight(BaseModel):
    """Structured output from sensitive data detection."""

    summary: str = Field(
        description="Brief sensitive data scan overview",
    )
    high_risk_items: list[str] = Field(
        description="High-risk data exposure items",
    )
    compliance_gaps: list[str] = Field(
        description="Compliance gaps from data exposure",
    )


class EncryptionInsight(BaseModel):
    """Structured output from encryption assessment."""

    summary: str = Field(
        description="Brief encryption assessment overview",
    )
    unencrypted_risks: list[str] = Field(
        description="Unencrypted storage risks",
    )
    upgrade_recommendations: list[str] = Field(
        description="Encryption upgrade recommendations",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of storage scan",
    )
    key_findings: list[str] = Field(
        description="Key findings for leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_PERMISSIONS = (
    "You are a cloud security analyst reviewing "
    "storage permission configurations.\n"
    "1. Identify buckets with public or overly "
    "permissive ACLs\n"
    "2. Flag cross-account access without "
    "justification\n"
    "3. Detect wildcard principal permissions\n"
    "4. Assess compliance with least-privilege "
    "principles"
)

SYSTEM_SENSITIVE_DATA = (
    "You are a data security analyst detecting "
    "sensitive data exposure in cloud storage.\n"
    "1. Identify PII, PHI, PCI, and credentials\n"
    "2. Assess exposure risk for each finding\n"
    "3. Map findings to compliance frameworks "
    "(HIPAA, PCI-DSS, GDPR)\n"
    "4. Prioritize by data sensitivity and "
    "public accessibility"
)

SYSTEM_ENCRYPTION = (
    "You are a cloud security analyst assessing "
    "encryption posture of storage buckets.\n"
    "1. Identify unencrypted buckets\n"
    "2. Evaluate encryption key management\n"
    "3. Check in-transit encryption enforcement\n"
    "4. Recommend encryption upgrades"
)

SYSTEM_REPORT = (
    "You are a security advisor generating an "
    "executive cloud storage security report.\n"
    "1. Summarize total findings by severity\n"
    "2. Highlight critical public exposure risks\n"
    "3. Quantify compliance gaps\n"
    "4. Recommend prioritized remediation steps"
)
