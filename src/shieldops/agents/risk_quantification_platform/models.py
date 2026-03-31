"""State models for the Risk Quantification Platform Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RiskStage(StrEnum):
    """Stages of the FAIR risk quantification workflow."""

    IDENTIFY_ASSETS = "identify_assets"
    ASSESS_THREATS = "assess_threats"
    MODEL_LOSS = "model_loss"
    CALCULATE_RISK = "calculate_risk"
    PRIORITIZE = "prioritize"
    REPORT = "report"


class LossCategory(StrEnum):
    """FAIR loss categories."""

    PRODUCTIVITY = "productivity"
    RESPONSE = "response"
    REPLACEMENT = "replacement"
    COMPETITIVE_ADVANTAGE = "competitive_advantage"
    FINES_JUDGMENTS = "fines_judgments"
    REPUTATION = "reputation"


class RiskTier(StrEnum):
    """Risk classification tiers."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class AssetRecord(BaseModel):
    """An asset identified for risk quantification."""

    id: str = ""
    name: str = ""
    asset_type: str = ""
    business_unit: str = ""
    criticality: float = 0.0
    data_classification: str = "internal"
    annual_revenue_impact: float = 0.0


class ThreatAssessment(BaseModel):
    """Threat assessment against an asset using FAIR factors."""

    id: str = ""
    asset_id: str = ""
    threat_type: str = ""
    threat_actor: str = ""
    contact_frequency: float = 0.0
    probability_of_action: float = 0.0
    vulnerability: float = 0.0
    loss_event_frequency: float = 0.0


class LossModel(BaseModel):
    """Loss magnitude model for a threat scenario."""

    id: str = ""
    threat_id: str = ""
    category: LossCategory = LossCategory.PRODUCTIVITY
    primary_loss_min: float = 0.0
    primary_loss_max: float = 0.0
    primary_loss_expected: float = 0.0
    secondary_loss_min: float = 0.0
    secondary_loss_max: float = 0.0
    secondary_loss_expected: float = 0.0
    annualized_loss_expectancy: float = 0.0


class RiskScore(BaseModel):
    """Computed risk score for a threat-asset pair."""

    id: str = ""
    asset_id: str = ""
    threat_id: str = ""
    loss_event_frequency: float = 0.0
    loss_magnitude: float = 0.0
    annualized_loss_expectancy: float = 0.0
    risk_tier: RiskTier = RiskTier.MEDIUM
    confidence: float = 0.0


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: int = 0
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskQuantificationState(BaseModel):
    """Full state of a risk quantification workflow."""

    # Identity
    request_id: str = ""
    stage: RiskStage = RiskStage.IDENTIFY_ASSETS
    tenant_id: str = ""

    # Data
    assets: list[dict[str, Any]] = Field(default_factory=list)
    threat_assessments: list[dict[str, Any]] = Field(default_factory=list)
    loss_models: list[dict[str, Any]] = Field(default_factory=list)
    risk_scores: list[dict[str, Any]] = Field(default_factory=list)
    prioritized_risks: list[dict[str, Any]] = Field(default_factory=list)

    # Metrics
    total_ale: float = 0.0
    assets_analyzed: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Tracking
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
