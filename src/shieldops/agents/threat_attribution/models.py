"""State models for Threat Attribution Agent."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class AttributionStage(StrEnum):
    """Stages in the threat attribution workflow."""

    COLLECT_EVIDENCE = "collect_evidence"
    MAP_TTPS = "map_ttps"
    PROFILE_ACTOR = "profile_actor"
    ASSESS_CONFIDENCE = "assess_confidence"
    GENERATE_REPORT = "generate_report"
    REPORT = "report"


class ThreatActorType(StrEnum):
    """Threat actor classification types."""

    APT = "apt"
    CYBERCRIME = "cybercrime"
    HACKTIVISM = "hacktivism"
    INSIDER = "insider"
    NATION_STATE = "nation_state"
    UNKNOWN = "unknown"


class ConfidenceLevel(StrEnum):
    """Attribution confidence levels."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNATTRIBUTED = "unattributed"


class TTPMapping(BaseModel):
    """MITRE ATT&CK TTP mapping entry."""

    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    description: str = ""
    data_sources: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class ActorProfile(BaseModel):
    """Threat actor profile."""

    name: str = ""
    actor_type: ThreatActorType = ThreatActorType.UNKNOWN
    aliases: list[str] = Field(default_factory=list)
    motivation: str = ""
    target_sectors: list[str] = Field(default_factory=list)
    known_ttps: list[str] = Field(default_factory=list)
    country_of_origin: str = ""


class AttributionAssessment(BaseModel):
    """Final attribution assessment."""

    attributed_actor: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.UNATTRIBUTED
    supporting_evidence: list[str] = Field(default_factory=list)
    alternative_hypotheses: list[str] = Field(default_factory=list)
    mitre_techniques_matched: int = 0
    summary: str = ""


class ThreatAttributionState(BaseModel):
    """Full state for the Threat Attribution Agent."""

    request_id: str = ""
    stage: AttributionStage = AttributionStage.COLLECT_EVIDENCE
    tenant_id: str = ""
    incident_id: str = ""
    ttp_mappings: list[TTPMapping] = Field(default_factory=list)
    actor_profile: ActorProfile = Field(
        default_factory=ActorProfile,
    )
    confidence: ConfidenceLevel = ConfidenceLevel.UNATTRIBUTED
    attribution_assessment: AttributionAssessment = Field(
        default_factory=AttributionAssessment,
    )
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
    session_start: float = 0.0
