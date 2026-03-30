"""LLM prompt templates for the Cloud Secret Vault Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -----------------------------------------


class SecretDiscoveryOutput(BaseModel):
    """Structured output for secret discovery analysis."""

    total_secrets: int = Field(
        description="Total secrets discovered",
    )
    unmanaged_count: int = Field(
        description="Number of unmanaged secrets",
    )
    summary: str = Field(
        description="Discovery summary",
    )


class RotationAuditOutput(BaseModel):
    """Structured output for rotation audit."""

    overdue_count: int = Field(
        description="Number of overdue rotations",
    )
    compliance_rate: float = Field(
        description="Rotation compliance rate 0-100",
    )
    reasoning: str = Field(
        description="Audit reasoning",
    )


class ExposureCheckOutput(BaseModel):
    """Structured output for exposure checking."""

    exposed_count: int = Field(
        description="Number of exposed secrets",
    )
    public_leaks: int = Field(
        description="Number of public leaks found",
    )
    reasoning: str = Field(
        description="Exposure check reasoning",
    )


class RiskAssessmentOutput(BaseModel):
    """Structured output for risk assessment."""

    max_risk_score: float = Field(
        description="Highest risk score 0-100",
    )
    critical_count: int = Field(
        description="Number of critical-risk secrets",
    )
    reasoning: str = Field(
        description="Risk assessment reasoning",
    )


class RemediationOutput(BaseModel):
    """Structured output for remediation recommendations."""

    actions: list[dict[str, str]] = Field(
        description="Remediation actions with priority",
    )
    total_risk_reduction: float = Field(
        description="Estimated total risk reduction 0-100",
    )
    reasoning: str = Field(
        description="Remediation reasoning",
    )


# -- System prompts ----------------------------------------------------

SYSTEM_DISCOVER = """\
You are an expert cloud security engineer performing \
secret and key discovery.

Given the scan configuration and target scope:
1. Enumerate all secrets across vault providers \
(AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, GCP Secret Manager)
2. Detect unmanaged secrets in environment variables and config files
3. Identify service accounts with embedded credentials
4. Flag secrets not tracked in any vault

Focus on: API keys, database credentials, SSH keys, \
TLS certificates, OAuth tokens, encryption keys."""

SYSTEM_ROTATION = """\
You are an expert cloud security engineer auditing \
secret rotation compliance.

Given the discovered secrets:
1. Check rotation policy compliance (90-day default)
2. Identify overdue rotations by severity
3. Detect secrets that have never been rotated
4. Assess rotation automation coverage

Prioritize secrets with high blast radius and \
compliance requirements (SOC2, PCI-DSS, HIPAA)."""

SYSTEM_EXPOSURE = """\
You are an expert cloud security engineer checking \
for secret exposure.

Given the discovered secrets:
1. Scan code repositories for hardcoded secrets
2. Check application logs for credential leakage
3. Search configuration files for unencrypted secrets
4. Monitor public breach databases for leaked keys

Use entropy analysis and pattern matching for detection."""

SYSTEM_RISK = """\
You are an expert cloud security engineer assessing \
secret risk levels.

Given the rotation audits and exposure checks:
1. Score risk based on exposure, rotation status, and type
2. Assess blast radius of potential compromise
3. Evaluate business impact and compliance implications
4. Map to regulatory requirements (SOC2, PCI-DSS)

Use a composite risk model with weighted factors."""

SYSTEM_REMEDIATE = """\
You are an expert cloud security engineer recommending \
secret remediation actions.

Given the risk assessments:
1. Prioritize immediate rotation for exposed secrets
2. Recommend vault migration for unmanaged secrets
3. Suggest automation for rotation compliance
4. Design access policy hardening measures

Balance urgency with operational disruption risk."""
