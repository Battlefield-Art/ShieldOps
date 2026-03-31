"""State models for the Deception Network Manager Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class DNMStage(StrEnum):
    """Stages in the deception network management lifecycle."""

    DEPLOY_DECOYS = "deploy_decoys"
    MONITOR_INTERACTIONS = "monitor_interactions"
    ANALYZE_BEHAVIOR = "analyze_behavior"
    CLASSIFY_ATTACKER = "classify_attacker"
    GENERATE_INTEL = "generate_intel"
    REPORT = "report"


class DecoyType(StrEnum):
    """Type of deception asset deployed."""

    HONEYPOT = "honeypot"
    HONEYTOKEN = "honeytoken"
    HONEYCRED = "honeycred"
    HONEYNET = "honeynet"
    BREADCRUMB = "breadcrumb"
    CANARY = "canary"


class AttackerProfile(StrEnum):
    """Classification of attacker sophistication."""

    SCRIPT_KIDDIE = "script_kiddie"
    OPPORTUNISTIC = "opportunistic"
    TARGETED = "targeted"
    APT = "apt"
    INSIDER = "insider"
    AUTOMATED = "automated"


# --- Domain models ---


class DeployedDecoy(BaseModel):
    """A deployed deception asset in the network."""

    decoy_id: str = ""
    decoy_type: DecoyType = DecoyType.HONEYPOT
    target_service: str = ""
    network_segment: str = ""
    deployed_at: datetime | None = None
    active: bool = True
    interactions: int = 0


class AttackerInteraction(BaseModel):
    """An interaction captured by a deception asset."""

    interaction_id: str = ""
    decoy_id: str = ""
    source_ip: str = ""
    technique: str = ""
    timestamp: datetime | None = None
    payload_hash: str = ""
    severity: str = "medium"


class BehaviorAnalysis(BaseModel):
    """Behavioral analysis of attacker activity."""

    analysis_id: str = ""
    source_ip: str = ""
    ttp_chain: list[str] = Field(default_factory=list)
    dwell_time_seconds: int = 0
    lateral_movement: bool = False
    data_exfil_attempted: bool = False
    risk_score: float = 0.0


class ThreatIntelReport(BaseModel):
    """Threat intelligence generated from deception data."""

    report_id: str = ""
    attacker_profile: AttackerProfile = AttackerProfile.OPPORTUNISTIC
    mitre_techniques: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    ttps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    confidence: float = 0.0


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the orchestrator workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class DeceptionNetworkManagerState(BaseModel):
    """Full state for a deception network manager run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: DNMStage = DNMStage.DEPLOY_DECOYS

    # Inputs
    network_segments: list[str] = Field(default_factory=list)
    decoy_types: list[DecoyType] = Field(default_factory=list)
    scope: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    decoys: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    interactions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    behaviors: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    intel: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_interactions: int = 0
    unique_attackers: int = 0
    high_risk_count: int = 0
    iocs_generated: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
