"""State models for the Attack Emulation Framework Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EmulationStage(StrEnum):
    """Stages of the adversary emulation workflow."""

    SELECT_ADVERSARY = "select_adversary"
    BUILD_CAMPAIGN = "build_campaign"
    EXECUTE_TECHNIQUES = "execute_techniques"
    MEASURE_DETECTION = "measure_detection"
    GENERATE_GAPS = "generate_gaps"
    REPORT = "report"


class TechniqueStatus(StrEnum):
    """Execution status of an emulated technique."""

    DETECTED = "detected"
    BLOCKED = "blocked"
    MISSED = "missed"
    PARTIAL = "partial"
    NOT_EXECUTED = "not_executed"
    ERROR = "error"


class AdversaryTier(StrEnum):
    """Threat actor sophistication tiers."""

    APT = "apt"
    ORGANIZED_CRIME = "organized_crime"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    OPPORTUNISTIC = "opportunistic"
    NATION_STATE = "nation_state"


class AdversaryProfile(BaseModel):
    """MITRE ATT&CK adversary profile."""

    id: str = ""
    name: str = ""
    aliases: list[str] = Field(default_factory=list)
    tier: AdversaryTier = AdversaryTier.APT
    target_sectors: list[str] = Field(default_factory=list)
    technique_count: int = 0
    description: str = ""


class CampaignTechnique(BaseModel):
    """A technique within an emulation campaign."""

    id: str = ""
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    procedure: str = ""
    status: TechniqueStatus = TechniqueStatus.NOT_EXECUTED
    detection_source: str = ""
    execution_time_ms: float = 0.0


class DetectionMeasurement(BaseModel):
    """Detection measurement for an executed technique."""

    id: str = ""
    technique_id: str = ""
    detected: bool = False
    blocked: bool = False
    detection_rule: str = ""
    detection_latency_ms: float = 0.0
    alert_generated: bool = False
    confidence: float = 0.0


class GapAnalysis(BaseModel):
    """Detection gap identified from emulation results."""

    id: str = ""
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    gap_type: str = ""
    severity: str = "medium"
    recommendation: str = ""
    estimated_effort: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: int = 0
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackEmulationState(BaseModel):
    """Full state of an attack emulation workflow."""

    # Identity
    request_id: str = ""
    stage: EmulationStage = EmulationStage.SELECT_ADVERSARY
    tenant_id: str = ""

    # Data
    adversary_profiles: list[dict[str, Any]] = Field(default_factory=list)
    campaign_techniques: list[dict[str, Any]] = Field(default_factory=list)
    detection_measurements: list[dict[str, Any]] = Field(default_factory=list)
    gap_analyses: list[dict[str, Any]] = Field(default_factory=list)
    selected_adversary: dict[str, Any] = Field(default_factory=dict)

    # Metrics
    detection_coverage_pct: float = 0.0
    techniques_executed: int = 0
    gaps_found: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Tracking
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
