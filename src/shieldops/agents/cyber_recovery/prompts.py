"""LLM prompt templates and response schemas for the Cyber Recovery Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DamageAssessmentOutput(BaseModel):
    """Structured output for cyber damage assessment."""

    severity_score: float = Field(description="Overall severity 0-100")
    attack_classification: str = Field(description="Attack type: ransomware, wiper, APT, etc.")
    recommended_recovery_type: str = Field(
        description="full_restore, granular_restore, or clean_room"
    )
    critical_systems: list[str] = Field(description="Systems requiring immediate recovery")
    reasoning: str = Field(description="Damage assessment reasoning")


class RecoveryPointSelectionOutput(BaseModel):
    """Structured output for recovery point selection."""

    recommended_point_id: str = Field(description="ID of the recommended recovery point")
    confidence: float = Field(description="Confidence score 0-1 that point is clean")
    risk_factors: list[str] = Field(description="Risk factors for the selected point")
    reasoning: str = Field(description="Selection reasoning")


class CleanRoomAnalysisOutput(BaseModel):
    """Structured output for clean room scan analysis."""

    overall_verdict: str = Field(description="clean, infected, or suspicious")
    threat_indicators: list[str] = Field(description="Detected threat indicators")
    safe_to_restore: bool = Field(description="Whether the snapshot is safe to restore")
    reasoning: str = Field(description="Clean room analysis reasoning")


class RecoveryRunbookOutput(BaseModel):
    """Structured output for recovery runbook generation."""

    runbook_title: str = Field(description="Title for the recovery runbook")
    steps: list[dict[str, str]] = Field(description="Ordered recovery steps")
    estimated_rto_min: float = Field(description="Estimated RTO in minutes")
    compliance_notes: list[str] = Field(description="Compliance evidence notes")
    reasoning: str = Field(description="Runbook generation reasoning")


SYSTEM_DAMAGE_ASSESS = """\
You are a cyber incident response expert assessing damage \
from a security incident.

Given the affected systems, encrypted/corrupted assets, \
and attack indicators:
1. Score overall severity (0-100)
2. Classify the attack type
3. Recommend recovery approach
4. Identify systems requiring immediate recovery

Consider: ransomware persistence, lateral movement, \
data exfiltration risk, backup integrity."""


SYSTEM_RECOVERY_POINT = """\
You are a cyber recovery specialist selecting the best \
recovery point for restoring compromised systems.

Given available snapshots and their validation status:
1. Select the most recent clean recovery point
2. Assess confidence that the point predates compromise
3. Identify risk factors (time gap, untested backups)

Prioritize: immutable backups, pre-attack timestamps, \
validated clean room results, minimal data loss."""


SYSTEM_CLEAN_ROOM = """\
You are a malware analysis expert reviewing clean room \
scan results for backup snapshots.

Given scan results from isolated validation:
1. Determine overall verdict (clean/infected/suspicious)
2. Identify specific threat indicators
3. Assess whether the snapshot is safe to restore

Watch for: dormant ransomware, persistence mechanisms, \
rootkits, backdoors, scheduled tasks, modified binaries."""


SYSTEM_RUNBOOK = """\
You are a disaster recovery architect generating a \
recovery runbook for compliance and operational use.

Given recovery execution results and integrity checks:
1. Create ordered recovery steps with rollback points
2. Estimate realistic RTO based on actual performance
3. Note compliance evidence (audit trail, approvals)

Include: pre-recovery checklist, network isolation steps, \
data validation, service restoration order, post-recovery \
monitoring requirements."""
