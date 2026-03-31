"""Attack Narrative Builder Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ANBStage(StrEnum):
    COLLECT_EVENTS = "collect_events"
    CORRELATE_TIMELINE = "correlate_timeline"
    RECONSTRUCT_CHAIN = "reconstruct_chain"
    MAP_TECHNIQUES = "map_techniques"
    BUILD_NARRATIVE = "build_narrative"
    REPORT = "report"


class EventSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AttackPhase(StrEnum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class SecurityEvent(BaseModel):
    """A raw security event for timeline reconstruction."""

    id: str = ""
    timestamp: str = ""
    source: str = ""
    event_type: str = ""
    severity: EventSeverity = EventSeverity.MEDIUM
    host: str = ""
    user: str = ""
    process: str = ""
    description: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)


class TimelineEntry(BaseModel):
    """A correlated entry in the attack timeline."""

    id: str = ""
    timestamp: str = ""
    event_ids: list[str] = Field(default_factory=list)
    description: str = ""
    severity: EventSeverity = EventSeverity.MEDIUM
    host: str = ""
    user: str = ""
    confidence: float = 0.0


class AttackChainLink(BaseModel):
    """A link in the reconstructed attack chain."""

    id: str = ""
    phase: AttackPhase = AttackPhase.INITIAL_ACCESS
    timeline_entry_id: str = ""
    description: str = ""
    host: str = ""
    user: str = ""
    technique: str = ""
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)


class TechniqueMapping(BaseModel):
    """MITRE ATT&CK technique mapping."""

    id: str = ""
    chain_link_id: str = ""
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    sub_technique: str = ""
    data_sources: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class NarrativeSection(BaseModel):
    """A section of the attack narrative."""

    id: str = ""
    phase: AttackPhase = AttackPhase.INITIAL_ACCESS
    title: str = ""
    body: str = ""
    timeline_refs: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackNarrativeBuilderState(BaseModel):
    """Main state for the Attack Narrative Builder agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: ANBStage = ANBStage.COLLECT_EVENTS

    security_events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    timeline_entries: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    attack_chain: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    technique_mappings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    narrative_sections: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    report: str = ""
    total_events_collected: int = 0
    attack_phases_identified: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
