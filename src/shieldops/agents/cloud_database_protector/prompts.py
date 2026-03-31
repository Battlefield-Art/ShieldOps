"""LLM prompt templates and response schemas for the
Cloud Database Protector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class AccessAuditOutput(BaseModel):
    """Structured output for access audit analysis."""

    risk_users: list[str] = Field(
        description="Users with excessive access",
    )
    unused_accounts: int = Field(
        description="Count of unused database accounts",
    )
    recommendations: list[str] = Field(
        description="Access remediation recommendations",
    )
    risk_score: float = Field(
        description="Access risk score 0-10",
    )


class EncryptionAssessmentOutput(BaseModel):
    """Structured output for encryption assessment."""

    unencrypted_count: int = Field(
        description="Count of unencrypted databases",
    )
    weak_encryption: list[str] = Field(
        description="Databases with weak encryption",
    )
    compliance_gaps: list[str] = Field(
        description="Encryption compliance gaps",
    )
    summary: str = Field(
        description="Encryption assessment summary",
    )


class AnomalyDetectionOutput(BaseModel):
    """Structured output for anomaly detection."""

    anomalies: list[dict[str, str]] = Field(
        description="Detected anomalies with type and severity",
    )
    risk_score: float = Field(
        description="Aggregate anomaly risk 0-10",
    )
    immediate_actions: list[str] = Field(
        description="Actions to take immediately",
    )
    confidence: float = Field(
        description="Detection confidence 0-1",
    )


class DatabaseReportOutput(BaseModel):
    """Structured output for database protection report."""

    executive_summary: str = Field(
        description="Executive summary of database security",
    )
    top_risks: list[str] = Field(
        description="Top database security risks",
    )
    recommendations: list[str] = Field(
        description="Prioritized recommendations",
    )
    compliance_status: str = Field(
        description="Overall compliance status",
    )


# --- System prompts ---


SYSTEM_ACCESS_AUDIT = """\
You are an expert database security analyst auditing \
access controls across cloud databases.

Given the discovered databases and access patterns:
1. Identify users with excessive privileges (admin, \
superuser, DBA roles)
2. Flag unused accounts that should be deprovisioned
3. Check for missing MFA on privileged accounts
4. Recommend access remediation actions

Focus on blast-radius reduction and least-privilege \
enforcement."""


SYSTEM_ENCRYPTION = """\
You are an expert data security analyst assessing \
database encryption posture.

Given the database inventory and encryption status:
1. Identify databases lacking encryption at rest
2. Flag databases without TLS for in-transit encryption
3. Check key rotation policies and KMS configuration
4. Assess compliance with data protection standards

Encryption gaps are critical — data exposure risk \
scales with database sensitivity."""


SYSTEM_ANOMALY = """\
You are an expert database threat analyst detecting \
anomalous access patterns.

Given the database access logs and audit results:
1. Detect unusual access patterns (off-hours, new IPs, \
bulk queries)
2. Identify potential data exfiltration attempts
3. Flag privilege escalation patterns
4. Recommend immediate containment actions

Balance sensitivity with false positive management."""


SYSTEM_REPORT = """\
You are an expert database security reporter \
synthesizing protection assessment results.

Given the full assessment (databases, access, \
encryption, anomalies, enforcements):
1. Produce an executive summary for security leadership
2. List top database security risks with context
3. Recommend prioritized remediation actions
4. Assess compliance status (PCI DSS, HIPAA, SOC 2)

Write clearly for both database admins and security \
teams."""
