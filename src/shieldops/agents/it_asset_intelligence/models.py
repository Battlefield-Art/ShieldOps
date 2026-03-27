"""IT Asset Intelligence Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AssetStage(StrEnum):
    DISCOVER_ASSETS = "discover_assets"
    CLASSIFY_CRITICALITY = "classify_criticality"
    ASSESS_SECURITY_POSTURE = "assess_security_posture"
    CORRELATE_WITH_THREATS = "correlate_with_threats"
    GENERATE_RISK_REPORT = "generate_risk_report"
    REPORT = "report"


class AssetCategory(StrEnum):
    SERVER = "server"
    ENDPOINT = "endpoint"
    NETWORK_DEVICE = "network_device"
    CLOUD_RESOURCE = "cloud_resource"
    AI_SYSTEM = "ai_system"
    IOT_DEVICE = "iot_device"


class RiskPosture(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    COMPLIANT = "compliant"


class ITAsset(BaseModel):
    """A discovered IT asset with metadata."""

    id: str = ""
    name: str = ""
    category: AssetCategory = AssetCategory.SERVER
    owner: str = ""
    location: str = ""
    os_version: str = ""
    last_seen: str = ""
    managed: bool = True
    tags: list[str] = Field(default_factory=list)


class CriticalityClassification(BaseModel):
    """Criticality classification for an asset."""

    asset_id: str = ""
    business_impact: str = ""
    data_sensitivity: str = ""
    criticality_score: float = Field(default=0.0, ge=0.0, le=10.0)
    dependencies: list[str] = Field(default_factory=list)
    tier: str = ""


class SecurityPosture(BaseModel):
    """Security posture assessment for an asset."""

    asset_id: str = ""
    vulnerability_count: int = 0
    patch_compliance_pct: float = Field(default=100.0, ge=0.0, le=100.0)
    encryption_enabled: bool = True
    edr_installed: bool = True
    posture: RiskPosture = RiskPosture.COMPLIANT
    findings: list[str] = Field(default_factory=list)


class ThreatCorrelation(BaseModel):
    """Threat correlation for an asset."""

    asset_id: str = ""
    threat_indicators: list[str] = Field(default_factory=list)
    attack_surface_score: float = Field(default=0.0, ge=0.0, le=10.0)
    active_threats: int = 0
    exposure_vector: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)


class AssetRiskReport(BaseModel):
    """Risk report for a single asset."""

    asset_id: str = ""
    asset_name: str = ""
    category: AssetCategory = AssetCategory.SERVER
    criticality_score: float = 0.0
    posture: RiskPosture = RiskPosture.COMPLIANT
    threat_score: float = 0.0
    composite_risk: float = 0.0
    recommendations: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ITAssetIntelligenceState(BaseModel):
    """Main state for the IT Asset Intelligence agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: AssetStage = AssetStage.DISCOVER_ASSETS

    # Discovered assets
    assets: list[ITAsset] = Field(default_factory=list)

    # Criticality classifications
    classifications: list[CriticalityClassification] = Field(default_factory=list)

    # Security postures
    postures: list[SecurityPosture] = Field(default_factory=list)

    # Threat correlations
    correlations: list[ThreatCorrelation] = Field(default_factory=list)

    # Risk reports
    risk_reports: list[AssetRiskReport] = Field(default_factory=list)

    # Summary
    report: str = ""
    total_assets: int = 0
    critical_count: int = 0

    # Reasoning
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)

    # Error
    error: str = ""
