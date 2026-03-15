"""Risk Scoring Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RiskStage(StrEnum):
    COLLECT = "collect"
    ENRICH = "enrich"
    AGGREGATE = "aggregate"
    SCORE = "score"
    DECIDE = "decide"


class MitreTactic(StrEnum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionDecision(StrEnum):
    AUTONOMOUS = "autonomous"
    HUMAN_APPROVAL = "human_approval"
    ESCALATE = "escalate"
    MONITOR = "monitor"


class SecurityObservation(BaseModel):
    """A single low-confidence security observation."""

    id: str = ""
    source: str = ""
    detection_name: str = ""
    mitre_tactic: MitreTactic = MitreTactic.DISCOVERY
    mitre_technique: str = ""
    raw_score: float = 0.0
    entity: str = ""  # user, host, IP
    entity_type: str = "host"
    timestamp: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskEntity(BaseModel):
    """An entity with aggregated risk from multiple observations."""

    entity: str = ""
    entity_type: str = "host"
    observations: list[SecurityObservation] = Field(default_factory=list)
    composite_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    tactics_seen: list[str] = Field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0


class RiskScoringState(BaseModel):
    """Main state for the Risk Scoring agent graph."""

    request_id: str = ""
    stage: RiskStage = RiskStage.COLLECT
    time_window_hours: int = 24

    # Observations
    raw_observations: list[SecurityObservation] = Field(default_factory=list)
    enriched_observations: list[SecurityObservation] = Field(default_factory=list)

    # Aggregation
    risk_entities: list[RiskEntity] = Field(default_factory=list)

    # Scoring thresholds
    autonomous_threshold: float = 0.85
    approval_threshold: float = 0.5

    # Decisions
    action_decisions: list[dict[str, Any]] = Field(default_factory=list)
    alerts_generated: list[dict[str, Any]] = Field(default_factory=list)

    # Output
    total_observations: int = 0
    high_risk_entities: int = 0
    recommendations: list[str] = Field(default_factory=list)
    confidence_score: float = 0.0
    reasoning_chain: list[str] = Field(default_factory=list)
