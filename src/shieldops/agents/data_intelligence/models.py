"""Data Intelligence Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DataIntelStage(StrEnum):
    DISCOVER_DATA = "discover_data"
    CLASSIFY_WITH_AI = "classify_with_ai"
    MAP_DATA_LINEAGE = "map_data_lineage"
    ASSESS_DATA_RISK = "assess_data_risk"
    RECOMMEND_PROTECTION = "recommend_protection"
    REPORT = "report"


class DataDomain(StrEnum):
    STRUCTURED = "structured"
    UNSTRUCTURED = "unstructured"
    SEMI_STRUCTURED = "semi_structured"
    AI_TRAINING = "ai_training"
    EMBEDDING = "embedding"
    MODEL_ARTIFACT = "model_artifact"


class ProtectionRecommendation(StrEnum):
    ENCRYPT = "encrypt"
    MASK = "mask"
    RESTRICT_ACCESS = "restrict_access"
    BACKUP = "backup"
    IMMUTABLE_LOCK = "immutable_lock"
    DELETE = "delete"


class DataDiscovery(BaseModel):
    """A discovered data source."""

    id: str = ""
    name: str = ""
    domain: DataDomain = DataDomain.STRUCTURED
    location: str = ""
    size_gb: float = 0.0
    record_count: int = 0
    owner: str = ""
    last_accessed: str = ""
    encrypted: bool = False


class AIClassification(BaseModel):
    """AI-powered data classification result."""

    data_id: str = ""
    sensitivity_level: str = ""
    data_types: list[str] = Field(default_factory=list)
    pii_detected: bool = False
    phi_detected: bool = False
    pci_detected: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    regulatory_frameworks: list[str] = Field(default_factory=list)


class DataLineage(BaseModel):
    """Data lineage mapping."""

    data_id: str = ""
    source_systems: list[str] = Field(default_factory=list)
    downstream_consumers: list[str] = Field(default_factory=list)
    transformations: list[str] = Field(default_factory=list)
    retention_days: int = 0
    cross_border: bool = False


class DataRisk(BaseModel):
    """Data risk assessment."""

    data_id: str = ""
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    exposure_type: str = ""
    access_violations: int = 0
    stale_permissions: int = 0
    compliance_gaps: list[str] = Field(default_factory=list)
    threat_vectors: list[str] = Field(default_factory=list)


class ProtectionPlan(BaseModel):
    """Protection plan for a data source."""

    data_id: str = ""
    data_name: str = ""
    risk_score: float = 0.0
    recommendations: list[ProtectionRecommendation] = Field(default_factory=list)
    priority: str = ""
    estimated_effort_hours: float = 0.0
    rationale: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class DataIntelligenceState(BaseModel):
    """Main state for the Data Intelligence agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: DataIntelStage = DataIntelStage.DISCOVER_DATA

    # Discovered data sources
    discoveries: list[DataDiscovery] = Field(default_factory=list)

    # AI classifications
    classifications: list[AIClassification] = Field(default_factory=list)

    # Data lineage
    lineages: list[DataLineage] = Field(default_factory=list)

    # Data risks
    risks: list[DataRisk] = Field(default_factory=list)

    # Protection plans
    plans: list[ProtectionPlan] = Field(default_factory=list)

    # Summary
    report: str = ""
    total_sources: int = 0
    high_risk_count: int = 0
    pii_sources: int = 0

    # Reasoning
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)

    # Error
    error: str = ""
