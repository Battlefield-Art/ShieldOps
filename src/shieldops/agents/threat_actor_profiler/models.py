"""State models for the Threat Actor Profiler Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class TAPStage(StrEnum):
    """Workflow stages for threat actor profiling."""

    COLLECT_INDICATORS = "collect_indicators"
    CLUSTER_ACTIVITY = "cluster_activity"
    BUILD_PROFILES = "build_profiles"
    MAP_TTPS = "map_ttps"
    ASSESS_TARGETING = "assess_targeting"
    REPORT = "report"


class ActorType(StrEnum):
    """Threat actor classification types."""

    APT = "apt"
    CYBERCRIMINAL = "cybercriminal"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    STATE_SPONSORED = "state_sponsored"
    UNKNOWN = "unknown"


class ConfidenceLevel(StrEnum):
    """Intelligence confidence levels."""

    CONFIRMED = "confirmed"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    UNVERIFIED = "unverified"


# ── Domain Models ─────────────────────────────────────


class Indicator(BaseModel):
    """A threat indicator collected from intelligence sources."""

    indicator_id: str = ""
    indicator_type: str = ""
    value: str = ""
    source: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.UNVERIFIED
    first_seen: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ActivityCluster(BaseModel):
    """A cluster of related threat activity."""

    cluster_id: str = ""
    indicator_ids: list[str] = Field(default_factory=list)
    common_ttps: list[str] = Field(default_factory=list)
    time_range: str = ""
    similarity_score: float = 0.0


class ActorProfile(BaseModel):
    """A threat actor profile."""

    profile_id: str = ""
    actor_name: str = ""
    actor_type: ActorType = ActorType.UNKNOWN
    cluster_ids: list[str] = Field(default_factory=list)
    known_aliases: list[str] = Field(default_factory=list)
    motivation: str = ""
    capability_level: str = ""


class TTPMapping(BaseModel):
    """MITRE ATT&CK TTP mapping for an actor."""

    profile_id: str = ""
    tactic: str = ""
    technique_id: str = ""
    technique_name: str = ""
    frequency: int = 0
    confidence: ConfidenceLevel = ConfidenceLevel.UNVERIFIED


class TargetingAssessment(BaseModel):
    """Assessment of an actor's targeting patterns."""

    profile_id: str = ""
    targeted_sectors: list[str] = Field(default_factory=list)
    targeted_regions: list[str] = Field(default_factory=list)
    risk_to_org: float = 0.0
    recommendations: list[str] = Field(default_factory=list)


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the threat actor profiling workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ThreatActorProfilerState(BaseModel):
    """Full state for the Threat Actor Profiler workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: TAPStage = TAPStage.COLLECT_INDICATORS
    config: dict[str, Any] = Field(default_factory=dict)

    indicators: list[dict[str, Any]] = Field(default_factory=list)
    clusters: list[dict[str, Any]] = Field(default_factory=list)
    profiles: list[dict[str, Any]] = Field(default_factory=list)
    ttp_mappings: list[dict[str, Any]] = Field(default_factory=list)
    targeting_assessments: list[dict[str, Any]] = Field(default_factory=list)

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
