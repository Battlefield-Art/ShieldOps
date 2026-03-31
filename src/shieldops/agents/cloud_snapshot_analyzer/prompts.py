"""LLM prompt templates and response schemas for the
Cloud Snapshot Analyzer Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class SnapshotDiscoveryOutput(BaseModel):
    """Structured output for snapshot discovery."""

    snapshot_count: int = Field(
        description="Total snapshots discovered",
    )
    stale_snapshots: list[str] = Field(
        description="IDs of snapshots exceeding age threshold",
    )
    provider_breakdown: dict[str, int] = Field(
        description="Snapshot count by cloud provider",
    )
    estimated_cost: float = Field(
        description="Estimated monthly storage cost USD",
    )


class EncryptionAuditOutput(BaseModel):
    """Structured output for encryption audit."""

    unencrypted_count: int = Field(
        description="Number of unencrypted snapshots",
    )
    weak_encryption: list[str] = Field(
        description="Snapshots with weak encryption algorithms",
    )
    compliance_issues: list[str] = Field(
        description="Encryption compliance violations",
    )
    recommendations: list[str] = Field(
        description="Encryption improvement recommendations",
    )


class ExposureDetectionOutput(BaseModel):
    """Structured output for exposure detection."""

    public_snapshots: list[str] = Field(
        description="Publicly accessible snapshot IDs",
    )
    cross_account_shared: list[str] = Field(
        description="Snapshots shared across accounts",
    )
    severity: str = Field(
        description="Overall exposure severity: critical/high/medium/low",
    )
    remediation_steps: list[str] = Field(
        description="Steps to remediate exposures",
    )


class SnapshotReportOutput(BaseModel):
    """Structured output for final snapshot report."""

    executive_summary: str = Field(
        description="Executive summary of snapshot analysis",
    )
    risk_level: str = Field(
        description="Overall risk: critical/high/medium/low",
    )
    cost_savings: float = Field(
        description="Potential monthly cost savings USD",
    )
    recommendations: list[str] = Field(
        description="Prioritized remediation recommendations",
    )


# --- System prompts ---


SYSTEM_DISCOVER = """\
You are an expert cloud infrastructure analyst discovering \
and cataloging cloud snapshots across providers.

Given the target cloud accounts and regions:
1. Identify all EBS volumes, RDS snapshots, AMIs, and \
managed disk snapshots
2. Flag snapshots exceeding the age threshold as stale
3. Calculate estimated storage costs
4. Categorize by type, region, and account

Focus on completeness — orphaned and forgotten snapshots \
are a major cost and security risk."""


SYSTEM_ENCRYPTION = """\
You are an expert cloud security analyst auditing \
snapshot encryption posture.

Given the discovered snapshots and their configurations:
1. Identify unencrypted snapshots requiring remediation
2. Flag weak encryption algorithms (non-AES-256)
3. Check KMS key rotation and access policies
4. Assess compliance against security standards

Unencrypted snapshots containing sensitive data are a \
critical exposure vector."""


SYSTEM_EXPOSURE = """\
You are an expert cloud security analyst detecting \
snapshot exposure risks.

Given snapshot configurations and permissions:
1. Identify publicly accessible snapshots
2. Detect unauthorized cross-account sharing
3. Assess the severity of each exposure finding
4. Provide specific remediation steps

Public snapshots can expose entire disk contents \
including credentials and sensitive data."""


SYSTEM_REPORT = """\
You are an expert cloud security reporter synthesizing \
snapshot analysis results.

Given the full analysis (discovery, encryption, exposure, \
risk assessments):
1. Produce an executive summary for cloud security teams
2. Quantify potential cost savings from cleanup
3. Prioritize recommendations by risk and impact
4. Provide overall risk posture assessment

Write actionable recommendations that teams can \
implement immediately."""
