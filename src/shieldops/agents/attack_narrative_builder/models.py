"""State models for the Attack Narrative Builder Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ANBStage(StrEnum):
    """Stages of the narrative-building pipeline."""

    COLLECT = "collect"
    CLUSTER = "cluster"
    TIMELINE = "timeline"
    NARRATE = "narrate"
    MITRE_MAP = "mitre_map"
    REPORT = "report"


class NarrativeType(StrEnum):
    """Types of attack narratives."""

    INCIDENT_SUMMARY = "incident_summary"
    THREAT_BRIEF = "threat_brief"
    EXECUTIVE_REPORT = "executive_report"
    TECHNICAL_DEEP_DIVE = "technical_deep_dive"
    HUNT_FINDING = "hunt_finding"


class KillChainPhase(StrEnum):
    """Lockheed Martin Cyber Kill Chain phases."""

    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class SecurityEvent(BaseModel):
    """A single security event from any source."""

    id: str = ""
    source: str = ""
    event_type: str = ""
    severity: str = "medium"
    timestamp: datetime | None = None
    host: str = ""
    user: str = ""
    action: str = ""
    outcome: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)
    ioc_indicators: list[str] = Field(default_factory=list)


class EventCluster(BaseModel):
    """A group of correlated security events."""

    id: str = ""
    label: str = ""
    event_ids: list[str] = Field(default_factory=list)
    kill_chain_phase: str = ""
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    confidence: float = 0.0
    earliest: datetime | None = None
    latest: datetime | None = None
    summary: str = ""


class NarrativeSegment(BaseModel):
    """A segment of the attack narrative (one stage of the attack)."""

    id: str = ""
    sequence: int = 0
    title: str = ""
    description: str = ""
    kill_chain_phase: str = ""
    mitre_technique_ids: list[str] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    event_count: int = 0
    time_range: str = ""


class AttackNarrative(BaseModel):
    """A complete human-readable attack narrative."""

    id: str = ""
    title: str = ""
    narrative_type: str = "incident_summary"
    executive_summary: str = ""
    segments: list[NarrativeSegment] = Field(default_factory=list)
    total_events: int = 0
    mitre_techniques: list[str] = Field(default_factory=list)
    kill_chain_coverage: dict[str, str] = Field(default_factory=dict)
    risk_rating: str = "medium"
    recommendations: list[str] = Field(default_factory=list)


class NarrativeReport(BaseModel):
    """Final output report for the narrative builder."""

    id: str = ""
    narrative: AttackNarrative | None = None
    clusters_analyzed: int = 0
    events_processed: int = 0
    mitre_techniques_mapped: int = 0
    kill_chain_phases_covered: int = 0
    generation_time_ms: int = 0
    quality_score: float = 0.0


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class AttackNarrativeBuilderState(BaseModel):
    """Full state of the attack narrative builder workflow."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: ANBStage = ANBStage.COLLECT

    # Configuration
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    events: list[dict[str, Any]] = Field(default_factory=list)
    clusters: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    narrative_segments: list[dict[str, Any]] = Field(default_factory=list)
    mitre_mappings: list[dict[str, Any]] = Field(default_factory=list)

    # Output
    report: dict[str, Any] = Field(default_factory=dict)

    # Tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
