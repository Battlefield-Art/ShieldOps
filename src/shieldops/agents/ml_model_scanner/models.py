"""State models for the ML Model Scanner Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class MMSStage(StrEnum):
    """Stages in the ML model scanning lifecycle."""

    DISCOVER_MODELS = "discover_models"
    SCAN_ARTIFACTS = "scan_artifacts"
    CHECK_PROVENANCE = "check_provenance"
    DETECT_BACKDOORS = "detect_backdoors"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class ModelFormat(StrEnum):
    """ML model serialization formats."""

    PICKLE = "pickle"
    SAFETENSORS = "safetensors"
    ONNX = "onnx"
    PYTORCH = "pytorch"
    TENSORFLOW = "tensorflow"
    GGUF = "gguf"


class RiskLevel(StrEnum):
    """Risk classification for model artifacts."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# --- Domain models ---


class ModelArtifact(BaseModel):
    """A discovered ML model artifact."""

    artifact_id: str = ""
    name: str = ""
    format: ModelFormat = ModelFormat.PICKLE
    size_bytes: int = 0
    registry: str = ""
    version: str = ""
    hash_sha256: str = ""
    location: str = ""
    discovered_at: datetime | None = None


class ScanResult(BaseModel):
    """Result from scanning a model artifact."""

    artifact_id: str = ""
    vulnerabilities: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    unsafe_operations: list[str] = Field(
        default_factory=list,
    )
    pickle_risk: bool = False
    risk_level: RiskLevel = RiskLevel.LOW
    scanner: str = ""


class ProvenanceRecord(BaseModel):
    """Provenance chain for a model artifact."""

    artifact_id: str = ""
    source_repo: str = ""
    training_data_hash: str = ""
    author: str = ""
    signed: bool = False
    sbom_available: bool = False
    lineage: list[str] = Field(default_factory=list)
    verified: bool = False


class BackdoorIndicator(BaseModel):
    """Indicator of potential model backdoor or poisoning."""

    artifact_id: str = ""
    indicator_type: str = ""
    confidence: float = 0.0
    description: str = ""
    affected_layers: list[str] = Field(
        default_factory=list,
    )
    severity: RiskLevel = RiskLevel.LOW


class RiskAssessment(BaseModel):
    """Aggregate risk assessment for a model artifact."""

    artifact_id: str = ""
    overall_risk: RiskLevel = RiskLevel.LOW
    risk_score: float = 0.0
    vulnerability_count: int = 0
    provenance_verified: bool = False
    backdoor_detected: bool = False
    recommendations: list[str] = Field(
        default_factory=list,
    )


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the scanner workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class MLModelScannerState(BaseModel):
    """Full state for an ML model scanner run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: MMSStage = MMSStage.DISCOVER_MODELS

    # Inputs
    scan_name: str = ""
    registries: list[str] = Field(default_factory=list)
    scope: dict[str, Any] = Field(default_factory=dict)
    formats_filter: list[str] = Field(default_factory=list)

    # Pipeline fields
    artifacts: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    scan_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    provenance_records: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    backdoor_indicators: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_models: int = 0
    vulnerable_models: int = 0
    critical_count: int = 0
    overall_risk_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
