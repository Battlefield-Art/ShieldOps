"""LLM prompt templates and response schemas for the
Cloud Forensics Collector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ScopeIdentificationOutput(BaseModel):
    """Structured output for forensic scope identification."""

    resources: list[dict[str, str]] = Field(
        description="Resources in scope with type and region",
    )
    evidence_types: list[str] = Field(
        description="Types of evidence to collect",
    )
    priority_resources: list[str] = Field(
        description="High-priority resources for immediate collection",
    )
    confidence: float = Field(
        description="Scope identification confidence 0-1",
    )


class LogAnalysisOutput(BaseModel):
    """Structured output for cloud log analysis."""

    suspicious_events: int = Field(
        description="Number of suspicious events found",
    )
    iocs: list[str] = Field(
        description="Indicators of compromise extracted",
    )
    timeline: list[dict[str, str]] = Field(
        description="Event timeline with timestamps and descriptions",
    )
    summary: str = Field(
        description="Log analysis summary",
    )


class EvidencePreservationOutput(BaseModel):
    """Structured output for evidence preservation."""

    preserved: bool = Field(
        description="Whether evidence was preserved successfully",
    )
    integrity_verified: bool = Field(
        description="Whether integrity hashes match",
    )
    chain_of_custody: list[str] = Field(
        description="Chain of custody entries",
    )
    storage_details: str = Field(
        description="Evidence storage location and format",
    )


class ForensicReportOutput(BaseModel):
    """Structured output for forensic investigation report."""

    executive_summary: str = Field(
        description="Executive summary for incident commander",
    )
    attack_timeline: list[str] = Field(
        description="Reconstructed attack timeline",
    )
    recommendations: list[str] = Field(
        description="Remediation and hardening recommendations",
    )
    severity_rating: str = Field(
        description="Incident severity: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_SCOPE = """\
You are an expert cloud forensics investigator \
identifying the scope of a security incident.

Given the incident details and cloud environment:
1. Identify all affected cloud resources and accounts
2. Determine the time window for evidence collection
3. Prioritize resources at highest risk of tampering
4. List evidence types needed per resource

Focus on AWS CloudTrail, GCP Audit Logs, Azure \
Activity Logs, disk snapshots, and network flow logs."""


SYSTEM_ANALYSIS = """\
You are an expert digital forensics analyst reviewing \
collected cloud evidence.

Given the collected logs, snapshots, and metadata:
1. Reconstruct the attack timeline from audit events
2. Extract indicators of compromise (IOCs)
3. Identify lateral movement and persistence mechanisms
4. Correlate events across cloud services and regions

Maintain forensic rigor. All findings must be \
evidence-backed and court-admissible."""


SYSTEM_PRESERVATION = """\
You are an expert evidence preservation specialist \
ensuring chain of custody integrity.

Given the collected forensic evidence:
1. Verify cryptographic integrity of all evidence
2. Document chain of custody for each artifact
3. Ensure tamper-proof storage with write-once locks
4. Validate evidence completeness against scope

Evidence must meet legal admissibility standards."""


SYSTEM_REPORT = """\
You are an expert forensic investigator writing the \
final incident investigation report.

Given the full forensic investigation (scope, evidence, \
analysis):
1. Produce an executive summary for incident command
2. Present the reconstructed attack timeline
3. List confirmed IOCs and affected systems
4. Recommend remediation and prevention measures

Write with forensic precision for both legal and \
technical audiences."""
