"""State models for the Unified Threat Model Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ----------------------------------------------------------


class UTMStage(StrEnum):
    """Workflow stages for unified threat modeling."""

    DEFINE_SCOPE = "define_scope"
    IDENTIFY_THREATS = "identify_threats"
    ANALYZE_CONTROLS = "analyze_controls"
    CALCULATE_RISK = "calculate_risk"
    PRIORITIZE = "prioritize"
    REPORT = "report"


class ThreatCategory(StrEnum):
    """STRIDE threat categories."""

    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class RiskLevel(StrEnum):
    """Risk level classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


# -- Domain Models -----------------------------------------------------


class ThreatScope(BaseModel):
    """Scope definition for threat modeling."""

    scope_id: str = ""
    name: str = ""
    description: str = ""
    assets: list[str] = Field(default_factory=list)
    data_flows: list[str] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IdentifiedThreat(BaseModel):
    """A threat identified during modeling."""

    threat_id: str = ""
    category: ThreatCategory = ThreatCategory.SPOOFING
    title: str = ""
    description: str = ""
    affected_asset: str = ""
    attack_vector: str = ""
    stride_element: str = ""
    dread_score: float = 0.0


class ControlAnalysis(BaseModel):
    """Analysis of existing security controls."""

    control_id: str = ""
    threat_id: str = ""
    control_type: str = ""
    effectiveness: float = 0.0
    gaps: list[str] = Field(default_factory=list)
    compensating: bool = False
    description: str = ""


class RiskCalculation(BaseModel):
    """Risk calculation for a threat."""

    threat_id: str = ""
    likelihood: float = 0.0
    impact: float = 0.0
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    residual_risk: float = 0.0
    reasoning: str = ""


class PrioritizedMitigation(BaseModel):
    """A prioritized mitigation recommendation."""

    mitigation_id: str = ""
    threat_id: str = ""
    priority: int = 0
    action: str = ""
    effort: str = ""
    risk_reduction: float = 0.0
    description: str = ""


# -- Reasoning + State -------------------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the threat model workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class UnifiedThreatModelState(BaseModel):
    """Full state for the Unified Threat Model workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: UTMStage = UTMStage.DEFINE_SCOPE
    config: dict[str, Any] = Field(default_factory=dict)

    # Scope
    threat_scope: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    asset_count: int = 0

    # Threats
    identified_threats: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    threat_count: int = 0

    # Controls
    control_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    control_gaps: int = 0

    # Risk
    risk_calculations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    max_risk_score: float = 0.0

    # Mitigations
    prioritized_mitigations: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
