"""Data Resilience Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ResilienceStage(StrEnum):
    INVENTORY_DATA_ASSETS = "inventory_data_assets"
    ASSESS_PROTECTION = "assess_protection"
    DETECT_ANOMALIES = "detect_anomalies"
    ENFORCE_IMMUTABILITY = "enforce_immutability"
    VALIDATE_RECOVERY = "validate_recovery"
    REPORT = "report"


class ProtectionLevel(StrEnum):
    IMMUTABLE = "immutable"
    VERSIONED = "versioned"
    REPLICATED = "replicated"
    UNPROTECTED = "unprotected"


class DataAssetType(StrEnum):
    DATABASE = "database"
    OBJECT_STORAGE = "object_storage"
    FILE_SYSTEM = "file_system"
    AI_MODEL = "ai_model"
    RAG_INDEX = "rag_index"
    TRAINING_DATA = "training_data"
    CONFIG = "config"


class DataAsset(BaseModel):
    """A data asset discovered during inventory."""

    id: str = ""
    name: str = ""
    asset_type: DataAssetType = DataAssetType.OBJECT_STORAGE
    cloud_provider: str = ""
    region: str = ""
    size_gb: float = 0.0
    last_modified: str = ""
    owner: str = ""
    classification: str = ""
    tags: dict[str, str] = Field(default_factory=dict)


class ProtectionAssessment(BaseModel):
    """Protection status assessment for a data asset."""

    id: str = ""
    asset_id: str = ""
    protection_level: ProtectionLevel = ProtectionLevel.UNPROTECTED
    has_object_lock: bool = False
    has_versioning: bool = False
    has_replication: bool = False
    has_backup: bool = False
    backup_age_hours: float = 0.0
    encryption_enabled: bool = False
    encryption_type: str = ""
    compliance_tags: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)


class DataAnomaly(BaseModel):
    """An anomaly detected on a data asset."""

    id: str = ""
    asset_id: str = ""
    anomaly_type: str = ""
    severity: str = ""
    description: str = ""
    detected_at: str = ""
    indicators: list[str] = Field(default_factory=list)
    is_ransomware_indicator: bool = False


class ImmutabilityEnforcement(BaseModel):
    """An immutability enforcement action applied to an asset."""

    id: str = ""
    asset_id: str = ""
    action: str = ""
    mechanism: str = ""
    retention_days: int = 0
    status: str = ""
    applied_at: str = ""
    rollback_available: bool = True


class RecoveryValidation(BaseModel):
    """Recovery validation test result for a data asset."""

    id: str = ""
    asset_id: str = ""
    test_type: str = ""
    recovery_time_seconds: float = 0.0
    recovery_point_age_hours: float = 0.0
    data_integrity_verified: bool = False
    checksum_match: bool = False
    status: str = ""
    notes: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class DataResilienceState(BaseModel):
    """Main state for the Data Resilience agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: ResilienceStage = ResilienceStage.INVENTORY_DATA_ASSETS

    # Inventoried data assets
    assets_inventoried: list[DataAsset] = Field(default_factory=list)

    # Protection assessments
    protection_assessments: list[ProtectionAssessment] = Field(default_factory=list)

    # Detected anomalies
    anomalies_detected: list[DataAnomaly] = Field(default_factory=list)

    # Enforcements applied
    enforcements_applied: list[ImmutabilityEnforcement] = Field(default_factory=list)

    # Recovery validations
    recovery_validated: list[RecoveryValidation] = Field(default_factory=list)

    # Summary / report
    recommendations: list[str] = Field(default_factory=list)
    report: str = ""

    # Stats
    total_assets: int = 0
    unprotected_count: int = 0
    anomaly_count: int = 0
    ransomware_indicators: int = 0
    resilience_score: float = Field(default=0.0, ge=0.0, le=100.0)

    # Reasoning
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)

    # Error
    error: str = ""
