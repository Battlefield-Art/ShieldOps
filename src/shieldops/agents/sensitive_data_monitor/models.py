"""Sensitive Data Monitor Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MonitorStage(StrEnum):
    DISCOVER_DATA_SOURCES = "discover_data_sources"
    SCAN_FOR_SENSITIVE = "scan_for_sensitive"
    CLASSIFY_DATA = "classify_data"
    ASSESS_EXPOSURE = "assess_exposure"
    ENFORCE_CONTROLS = "enforce_controls"
    REPORT = "report"


class DataCategory(StrEnum):
    PII = "pii"
    PHI = "phi"
    PCI = "pci"
    INTELLECTUAL_PROPERTY = "intellectual_property"
    CREDENTIALS = "credentials"
    CLASSIFIED = "classified"


class ExposureLevel(StrEnum):
    PUBLIC = "public"
    SHARED = "shared"
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    ENCRYPTED = "encrypted"


class DataSource(BaseModel):
    """A data source discovered for monitoring."""

    id: str = ""
    name: str = ""
    source_type: str = ""
    location: str = ""
    owner: str = ""
    records_count: int = 0
    size_gb: float = 0.0
    is_ai_pipeline: bool = False
    pipeline_type: str = ""
    last_scanned: float = 0.0
    scan_frequency_hours: int = 24


class SensitiveDataHit(BaseModel):
    """A detected sensitive data element within a source."""

    id: str = ""
    source_id: str = ""
    data_category: DataCategory = DataCategory.PII
    column_or_path: str = ""
    sample_count: int = 0
    confidence: float = 0.0
    detection_method: str = ""
    regex_matched: bool = False
    ml_classified: bool = False
    data_lineage: list[str] = Field(default_factory=list)


class Classification(BaseModel):
    """Final classification applied to a sensitive data hit."""

    id: str = ""
    hit_id: str = ""
    source_id: str = ""
    data_category: DataCategory = DataCategory.PII
    exposure_level: ExposureLevel = ExposureLevel.INTERNAL
    risk_score: float = 0.0
    regulations: list[str] = Field(default_factory=list)
    requires_encryption: bool = False
    requires_masking: bool = False


class ExposureAssessment(BaseModel):
    """Exposure risk assessment for a classified data element."""

    id: str = ""
    classification_id: str = ""
    source_id: str = ""
    exposure_level: ExposureLevel = ExposureLevel.INTERNAL
    access_principals: int = 0
    is_publicly_accessible: bool = False
    has_encryption_at_rest: bool = False
    has_encryption_in_transit: bool = False
    risk_score: float = 0.0
    remediation_actions: list[str] = Field(default_factory=list)


class ControlEnforcement(BaseModel):
    """Record of a control action enforced on a data source."""

    id: str = ""
    source_id: str = ""
    control_type: str = ""
    action_taken: str = ""
    applied: bool = False
    success: bool = False
    rollback_available: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SensitiveDataMonitorState(BaseModel):
    """Main state for the Sensitive Data Monitor graph."""

    # Input
    request_id: str = ""
    stage: MonitorStage = MonitorStage.DISCOVER_DATA_SOURCES
    tenant_id: str = ""

    # Data
    sources_scanned: list[dict[str, Any]] = Field(default_factory=list)
    sensitive_hits: list[dict[str, Any]] = Field(default_factory=list)
    classifications: list[dict[str, Any]] = Field(default_factory=list)
    exposures: list[dict[str, Any]] = Field(default_factory=list)
    controls_enforced: list[dict[str, Any]] = Field(default_factory=list)

    # Coverage
    compliance_coverage: dict[str, Any] = Field(default_factory=dict)

    # Stats
    stats: dict[str, Any] = Field(default_factory=dict)

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
