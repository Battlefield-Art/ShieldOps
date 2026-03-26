"""Cloud Risk Ranker Agent — Pydantic state and data models."""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RankerStage(StrEnum):
    COLLECT_CLOUD_FINDINGS = "collect_cloud_findings"
    CORRELATE_ATTACKER_TACTICS = "correlate_attacker_tactics"
    RANK_BY_EXPLOITABILITY = "rank_by_exploitability"
    GENERATE_ATTACK_PATHS = "generate_attack_paths"
    PRIORITIZE_REMEDIATION = "prioritize_remediation"
    REPORT = "report"


class RiskCategory(StrEnum):
    MISCONFIGURATION = "misconfiguration"
    VULNERABILITY = "vulnerability"
    IDENTITY_EXPOSURE = "identity_exposure"
    DATA_EXPOSURE = "data_exposure"
    NETWORK_EXPOSURE = "network_exposure"


class ExploitabilityLevel(StrEnum):
    ACTIVELY_EXPLOITED = "actively_exploited"
    EXPLOIT_AVAILABLE = "exploit_available"
    PROOF_OF_CONCEPT = "proof_of_concept"
    THEORETICAL = "theoretical"


class CloudFinding(BaseModel):
    """A security finding from a cloud environment."""

    id: str = ""
    provider: str = "aws"
    resource_type: str = ""
    resource_id: str = ""
    region: str = ""
    category: RiskCategory = RiskCategory.MISCONFIGURATION
    severity: str = "medium"
    title: str = ""
    description: str = ""
    cve_id: str = ""
    first_seen: float = Field(default_factory=time.time)
    tags: dict[str, str] = Field(default_factory=dict)


class AttackerTactic(BaseModel):
    """A MITRE ATT&CK tactic correlated to a cloud finding."""

    id: str = ""
    finding_id: str = ""
    tactic_id: str = ""
    tactic_name: str = ""
    technique_id: str = ""
    technique_name: str = ""
    procedure: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    known_campaigns: list[str] = Field(default_factory=list)


class ExploitabilityAssessment(BaseModel):
    """Exploitability scoring for a finding."""

    id: str = ""
    finding_id: str = ""
    level: ExploitabilityLevel = ExploitabilityLevel.THEORETICAL
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0)
    in_cisa_kev: bool = False
    days_since_disclosure: int = 0
    exploit_maturity: str = ""
    weapon_ready: bool = False
    composite_score: float = Field(default=0.0, ge=0.0, le=100.0)


class AttackPath(BaseModel):
    """An attack path linking finding to tactic to impact."""

    id: str = ""
    entry_finding_id: str = ""
    steps: list[dict[str, Any]] = Field(default_factory=list)
    impact: str = ""
    blast_radius: str = ""
    likelihood: float = Field(default=0.0, ge=0.0, le=1.0)
    business_criticality: str = "medium"
    overall_risk_score: float = Field(default=0.0, ge=0.0, le=100.0)


class RemediationPriority(BaseModel):
    """A prioritized remediation recommendation."""

    id: str = ""
    finding_id: str = ""
    rank: int = 0
    action: str = ""
    effort: str = "medium"
    risk_reduction: float = Field(default=0.0, ge=0.0, le=100.0)
    estimated_hours: float = 0.0
    auto_remediable: bool = False
    business_justification: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudRiskRankerState(BaseModel):
    """Main state for the Cloud Risk Ranker agent graph."""

    request_id: str = ""
    stage: RankerStage = RankerStage.COLLECT_CLOUD_FINDINGS
    tenant_id: str = ""
    providers: list[str] = Field(default_factory=list)

    # Collected findings
    findings: list[dict[str, Any]] = Field(default_factory=list)
    findings_count: int = 0

    # Correlated tactics
    tactics: list[dict[str, Any]] = Field(default_factory=list)

    # Exploitability assessments
    assessments: list[dict[str, Any]] = Field(default_factory=list)

    # Attack paths
    attack_paths: list[dict[str, Any]] = Field(default_factory=list)

    # Remediation priorities
    remediation_priorities: list[dict[str, Any]] = Field(default_factory=list)

    # Summary metrics
    critical_risks: int = 0
    mean_time_to_remediate: float = 0.0

    # Stats / summary
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""

    # Timing
    session_start: float = Field(default_factory=time.time)
    session_duration_ms: float = 0.0

    # Error
    error: str = ""
