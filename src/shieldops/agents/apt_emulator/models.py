"""State models for the APT Emulator Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EmulatorStage(StrEnum):
    """Stages of the APT emulation workflow."""

    DESIGN_CAMPAIGN = "design_campaign"
    EXECUTE_RECON = "execute_recon"
    SIMULATE_ACCESS = "simulate_access"
    TEST_PERSISTENCE = "test_persistence"
    TEST_LATERAL = "test_lateral"
    TEST_EXFIL = "test_exfil"
    REPORT = "report"


class APTPhase(StrEnum):
    """MITRE ATT&CK-aligned APT kill chain phases."""

    RECON = "recon"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"


class CampaignResult(StrEnum):
    """Outcome of a campaign phase against defenses."""

    BLOCKED = "blocked"
    DETECTED = "detected"
    PARTIALLY_DETECTED = "partially_detected"
    EVADED = "evaded"


class CampaignDesign(BaseModel):
    """High-level design for an APT emulation campaign."""

    id: str = ""
    apt_group: str = ""
    campaign_name: str = ""
    target_environment: str = ""
    phases: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    objectives: list[str] = Field(default_factory=list)
    safety_constraints: list[str] = Field(default_factory=list)


class ReconResult(BaseModel):
    """Results from the reconnaissance simulation phase."""

    id: str = ""
    target: str = ""
    technique_id: str = ""
    data_gathered: list[str] = Field(default_factory=list)
    exposed_services: list[str] = Field(default_factory=list)
    result: CampaignResult = CampaignResult.DETECTED
    confidence: float = 0.0


class AccessSimulation(BaseModel):
    """Results from initial access simulation."""

    id: str = ""
    technique_id: str = ""
    vector: str = ""
    target: str = ""
    result: CampaignResult = CampaignResult.BLOCKED
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class PersistenceTest(BaseModel):
    """Results from persistence mechanism testing."""

    id: str = ""
    technique_id: str = ""
    mechanism: str = ""
    target: str = ""
    result: CampaignResult = CampaignResult.BLOCKED
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class LateralTest(BaseModel):
    """Results from lateral movement testing."""

    id: str = ""
    technique_id: str = ""
    source: str = ""
    destination: str = ""
    protocol: str = ""
    result: CampaignResult = CampaignResult.BLOCKED
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class ExfilTest(BaseModel):
    """Results from exfiltration testing."""

    id: str = ""
    technique_id: str = ""
    channel: str = ""
    data_type: str = ""
    volume_mb: float = 0.0
    result: CampaignResult = CampaignResult.BLOCKED
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class APTEmulatorState(BaseModel):
    """Full state of an APT emulation workflow."""

    # Identity
    request_id: str = ""
    stage: EmulatorStage = EmulatorStage.DESIGN_CAMPAIGN
    tenant_id: str = ""

    # Data
    campaign: CampaignDesign = Field(default_factory=CampaignDesign)
    recon_results: list[ReconResult] = Field(default_factory=list)
    access_results: list[AccessSimulation] = Field(default_factory=list)
    persistence_results: list[PersistenceTest] = Field(default_factory=list)
    lateral_results: list[LateralTest] = Field(default_factory=list)
    exfil_results: list[ExfilTest] = Field(default_factory=list)

    # Metrics
    phases_blocked: int = 0
    phases_evaded: int = 0
    overall_score: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Tracking
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
