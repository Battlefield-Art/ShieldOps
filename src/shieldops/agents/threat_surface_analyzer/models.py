"""State models for the Threat Surface Analyzer Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TSAStage(StrEnum):
    """Stages of the threat surface analysis lifecycle."""

    DISCOVER_ASSETS = "discover_assets"
    MAP_EXPOSURE = "map_exposure"
    ASSESS_RISKS = "assess_risks"
    PRIORITIZE_THREATS = "prioritize_threats"
    RECOMMEND_MITIGATIONS = "recommend_mitigations"
    REPORT = "report"


class ExposureType(StrEnum):
    """Types of exposure identified on the threat surface."""

    PUBLIC_ENDPOINT = "public_endpoint"
    MISCONFIGURED_SERVICE = "misconfigured_service"
    UNPATCHED_VULNERABILITY = "unpatched_vulnerability"
    EXPOSED_CREDENTIAL = "exposed_credential"
    SHADOW_IT = "shadow_it"
    OVERPRIVILEGED_IDENTITY = "overprivileged_identity"
    INSECURE_API = "insecure_api"
    OPEN_PORT = "open_port"


class RiskCategory(StrEnum):
    """Risk categories for threat surface findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AssetExposure(BaseModel):
    """An asset discovered on the threat surface with exposure details."""

    asset_id: str = ""
    asset_name: str = ""
    asset_type: str = ""
    environment: str = ""
    exposure_type: ExposureType = ExposureType.PUBLIC_ENDPOINT
    exposure_details: str = ""
    discovered_at: datetime | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ThreatVector(BaseModel):
    """A threat vector mapped from asset exposures."""

    vector_id: str = ""
    source_asset_ids: list[str] = Field(default_factory=list)
    attack_path: str = ""
    exploitability: float = Field(default=0.0, ge=0.0, le=1.0)
    impact: float = Field(default=0.0, ge=0.0, le=1.0)
    mitre_techniques: list[str] = Field(default_factory=list)
    description: str = ""


class RiskAssessment(BaseModel):
    """Risk assessment result for a threat vector."""

    assessment_id: str = ""
    vector_id: str = ""
    risk_category: RiskCategory = RiskCategory.INFORMATIONAL
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    likelihood: float = Field(default=0.0, ge=0.0, le=1.0)
    impact_score: float = Field(default=0.0, ge=0.0, le=1.0)
    affected_assets: list[str] = Field(default_factory=list)
    justification: str = ""


class MitigationPlan(BaseModel):
    """A recommended mitigation action for an assessed risk."""

    mitigation_id: str = ""
    assessment_id: str = ""
    action: str = ""
    priority: str = "medium"
    estimated_effort: str = ""
    expected_risk_reduction: float = Field(default=0.0, ge=0.0, le=1.0)
    owner: str = ""
    description: str = ""


class SurfaceReport(BaseModel):
    """Summary report of a complete threat surface analysis."""

    report_id: str = ""
    title: str = ""
    executive_summary: str = ""
    assets_discovered: int = 0
    exposures_mapped: int = 0
    risks_assessed: int = 0
    critical_count: int = 0
    high_count: int = 0
    mitigations_recommended: int = 0
    overall_risk_score: float = 0.0
    generated_at: datetime | None = None


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ThreatSurfaceAnalyzerState(BaseModel):
    """Full LangGraph state for the Threat Surface Analyzer agent."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: TSAStage = TSAStage.DISCOVER_ASSETS
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    assets: list[dict[str, Any]] = Field(default_factory=list)
    exposures: list[dict[str, Any]] = Field(default_factory=list)
    risks: list[dict[str, Any]] = Field(default_factory=list)
    priorities: list[dict[str, Any]] = Field(default_factory=list)
    mitigations: list[dict[str, Any]] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)

    # Metrics
    critical_count: int = 0
    high_count: int = 0
    overall_risk_score: float = 0.0

    # Metadata
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
