"""Data Pipeline Protector Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DPPStage(StrEnum):
    DISCOVER_PIPELINES = "discover_pipelines"
    SCAN_INPUTS = "scan_inputs"
    DETECT_ANOMALIES = "detect_anomalies"
    VALIDATE_SCHEMAS = "validate_schemas"
    ENFORCE_ACCESS = "enforce_access"
    REPORT = "report"


class PipelineRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class DataSourceType(StrEnum):
    DATABASE = "database"
    API = "api"
    STREAM = "stream"
    FILE_SYSTEM = "file_system"
    CLOUD_STORAGE = "cloud_storage"
    ML_DATASET = "ml_dataset"


# --- Domain models ---


class DataPipeline(BaseModel):
    """A discovered data pipeline with metadata."""

    id: str = ""
    name: str = ""
    pipeline_type: str = ""
    source_type: DataSourceType = DataSourceType.DATABASE
    source_uri: str = ""
    destination_uri: str = ""
    owner: str = ""
    schedule: str = ""
    last_run: float = 0.0
    record_count: int = 0
    risk: PipelineRisk = PipelineRisk.LOW


class InputScan(BaseModel):
    """Result of scanning pipeline input data."""

    id: str = ""
    pipeline_id: str = ""
    scan_type: str = ""
    threat_category: str = ""
    description: str = ""
    severity: PipelineRisk = PipelineRisk.MEDIUM
    confidence: float = 0.0
    affected_records: int = 0
    mitre_technique: str = ""
    sample_payload: str = ""


class DataAnomaly(BaseModel):
    """An anomaly detected in pipeline data flow."""

    id: str = ""
    pipeline_id: str = ""
    anomaly_type: str = ""
    description: str = ""
    severity: PipelineRisk = PipelineRisk.MEDIUM
    baseline_value: float = 0.0
    observed_value: float = 0.0
    deviation_pct: float = 0.0
    detected_at: float = 0.0


class SchemaValidation(BaseModel):
    """Result of schema drift or tampering check."""

    id: str = ""
    pipeline_id: str = ""
    field_name: str = ""
    expected_type: str = ""
    actual_type: str = ""
    drift_type: str = ""
    severity: PipelineRisk = PipelineRisk.MEDIUM
    description: str = ""
    is_breaking: bool = False


class AccessEnforcement(BaseModel):
    """An access control enforcement action."""

    id: str = ""
    pipeline_id: str = ""
    principal: str = ""
    action: str = ""
    resource: str = ""
    decision: str = ""
    policy_name: str = ""
    severity: PipelineRisk = PipelineRisk.MEDIUM
    auto_remediated: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


# --- Main state ---


class DataPipelineProtectorState(BaseModel):
    """Main state for the Data Pipeline Protector agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: DPPStage = DPPStage.DISCOVER_PIPELINES

    # Input
    target_environment: str = ""
    pipeline_ids: list[str] = Field(default_factory=list)
    scan_scope: list[str] = Field(default_factory=list)

    # Pipeline outputs
    discovered_pipelines: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    input_scans: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    data_anomalies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    schema_validations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    access_enforcements: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
