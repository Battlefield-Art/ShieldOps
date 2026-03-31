"""LLM prompt templates and response schemas for the
Backup Integrity Verifier Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class BackupDiscoveryOutput(BaseModel):
    """Structured output for backup discovery analysis."""

    backups: list[dict[str, str]] = Field(
        description="List of discovered backups with type and location",
    )
    coverage_gaps: list[str] = Field(
        description="Systems missing backup coverage",
    )
    recommendations: list[str] = Field(
        description="Backup strategy recommendations",
    )
    confidence: float = Field(
        description="Discovery confidence 0-1",
    )


class IntegrityAnalysisOutput(BaseModel):
    """Structured output for integrity verification analysis."""

    passed_count: int = Field(
        description="Number of backups passing integrity",
    )
    failed_count: int = Field(
        description="Number of backups failing integrity",
    )
    risk_assessment: str = Field(
        description="Overall risk: critical/high/medium/low",
    )
    summary: str = Field(
        description="Integrity verification summary",
    )


class RestoreTestOutput(BaseModel):
    """Structured output for restore test analysis."""

    success_rate: float = Field(
        description="Restore success rate 0-1",
    )
    rpo_compliance: bool = Field(
        description="Whether RPO targets are met",
    )
    rto_compliance: bool = Field(
        description="Whether RTO targets are met",
    )
    issues: list[str] = Field(
        description="Restore issues identified",
    )
    recommendations: list[str] = Field(
        description="Restore improvement recommendations",
    )


class VerificationReportOutput(BaseModel):
    """Structured output for final verification report."""

    executive_summary: str = Field(
        description="Executive summary of backup health",
    )
    overall_health: str = Field(
        description="Overall health: healthy/degraded/critical",
    )
    recommendations: list[str] = Field(
        description="Prioritized recommendations",
    )
    compliance_status: str = Field(
        description="Compliance: compliant/non-compliant/partial",
    )
    risk_rating: str = Field(
        description="Risk rating: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_DISCOVER = """\
You are an expert backup and disaster recovery analyst \
discovering and cataloging backup assets.

Given the target systems and storage locations:
1. Identify all backup types (full, incremental, snapshot)
2. Detect coverage gaps where critical systems lack backups
3. Assess backup freshness and retention compliance
4. Recommend improvements to backup strategy

Focus on critical data: databases, configuration stores, \
secrets vaults, and compliance-relevant archives."""


SYSTEM_INTEGRITY = """\
You are an expert data integrity analyst verifying \
backup integrity and consistency.

Given the integrity check results:
1. Assess overall backup health and reliability
2. Identify patterns in integrity failures (corruption, \
truncation, version mismatches)
3. Prioritize remediation by business impact
4. Evaluate risk of data loss from failed backups

Be precise about failure modes and root causes."""


SYSTEM_RESTORE = """\
You are an expert disaster recovery analyst evaluating \
backup restore test results.

Given restore test outcomes:
1. Assess RPO and RTO compliance across systems
2. Identify restore bottlenecks and failure points
3. Evaluate data integrity post-restore
4. Recommend improvements to restore procedures

Consider regulatory requirements for recovery testing."""


SYSTEM_REPORT = """\
You are an expert backup operations reporter synthesizing \
verification results.

Given the full verification campaign (discovery, integrity, \
encryption, restore tests):
1. Produce an executive summary for IT leadership
2. Rate overall backup program health
3. List prioritized recommendations for improvement
4. Assess compliance with backup policies and regulations

Write clearly for both technical and non-technical \
audiences."""
