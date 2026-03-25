"""Data Classification Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ClassificationStage(StrEnum):
    SCAN_SOURCES = "scan_sources"
    DETECT_SENSITIVE = "detect_sensitive"
    CLASSIFY_LEVEL = "classify_level"
    MAP_REGULATIONS = "map_regulations"
    ENFORCE_LABELS = "enforce_labels"
    REPORT = "report"


class SensitivityLevel(StrEnum):
    TOP_SECRET = "top_secret"  # noqa: S105
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"
    UNCLASSIFIED = "unclassified"


class DataCategory(StrEnum):
    PII = "pii"
    PHI = "phi"
    PCI = "pci"
    CREDENTIALS = "credentials"
    INTELLECTUAL_PROPERTY = "intellectual_property"
    BUSINESS_CRITICAL = "business_critical"


class DataAsset(BaseModel):
    """A data source or storage asset to be classified."""

    id: str = ""
    name: str = ""
    asset_type: str = ""  # database / s3_bucket / gcs_bucket / blob_storage / file_share
    location: str = ""
    owner: str = ""
    records_count: int = 0
    size_gb: float = 0.0
    last_scanned: float = 0.0


class SensitiveDataFinding(BaseModel):
    """A detected sensitive data element within an asset."""

    id: str = ""
    asset_id: str = ""
    data_category: DataCategory = DataCategory.PII
    sensitivity_level: SensitivityLevel = SensitivityLevel.UNCLASSIFIED
    column_or_path: str = ""
    sample_count: int = 0
    confidence: float = 0.0
    regex_matched: bool = False
    llm_classified: bool = False


class RegulatoryMapping(BaseModel):
    """Mapping of a finding to a regulatory requirement."""

    id: str = ""
    finding_id: str = ""
    regulation: str = ""  # GDPR / HIPAA / PCI_DSS / CCPA / SOX
    requirement: str = ""
    compliant: bool = False
    gap_description: str = ""


class LabelEnforcement(BaseModel):
    """Record of a classification label applied to an asset."""

    id: str = ""
    asset_id: str = ""
    label_applied: str = ""
    enforcement_method: str = ""
    applied: bool = False
    success: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class DataClassificationState(BaseModel):
    """Main state for the Data Classification graph."""

    # Input
    request_id: str = ""
    stage: ClassificationStage = ClassificationStage.SCAN_SOURCES
    tenant_id: str = ""

    # Data
    data_assets: list[dict[str, Any]] = Field(default_factory=list)
    sensitive_findings: list[dict[str, Any]] = Field(default_factory=list)
    regulatory_mappings: list[dict[str, Any]] = Field(default_factory=list)
    label_enforcements: list[dict[str, Any]] = Field(default_factory=list)

    # Stats
    stats: dict[str, Any] = Field(default_factory=dict)

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
