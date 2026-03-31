"""Security Data Pipeline Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SDPStage(StrEnum):
    INGEST_SOURCES = "ingest_sources"
    TRANSFORM_DATA = "transform_data"
    ENRICH = "enrich"
    VALIDATE_QUALITY = "validate_quality"
    LOAD_DESTINATION = "load_destination"
    REPORT = "report"


class DataSourceType(StrEnum):
    SIEM = "siem"
    EDR = "edr"
    FIREWALL = "firewall"
    CLOUD_TRAIL = "cloud_trail"
    IDENTITY = "identity"
    VULNERABILITY = "vulnerability"


class QualityLevel(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    FAILED = "failed"
    UNKNOWN = "unknown"


class IngestedRecord(BaseModel):
    """A single ingested security data record."""

    id: str = ""
    source: DataSourceType = DataSourceType.SIEM
    timestamp: str = ""
    raw_size_bytes: int = 0
    schema_version: str = ""
    event_type: str = ""
    fields: dict[str, Any] = Field(default_factory=dict)


class TransformedRecord(BaseModel):
    """A normalized and transformed security record."""

    id: str = ""
    source: DataSourceType = DataSourceType.SIEM
    normalized_schema: str = "OCSF"
    event_type: str = ""
    severity: str = "info"
    timestamp: str = ""
    enrichments_applied: int = 0
    fields: dict[str, Any] = Field(default_factory=dict)


class EnrichmentResult(BaseModel):
    """Result of IOC / context enrichment."""

    id: str = ""
    record_id: str = ""
    enrichment_type: str = ""
    matched: bool = False
    ioc_value: str = ""
    threat_score: float = 0.0
    source_feed: str = ""


class QualityCheck(BaseModel):
    """Data quality validation result."""

    id: str = ""
    check_name: str = ""
    passed: bool = True
    records_checked: int = 0
    records_failed: int = 0
    quality_level: QualityLevel = QualityLevel.HIGH
    detail: str = ""


class LoadResult(BaseModel):
    """Result of loading data to destination."""

    id: str = ""
    destination: str = ""
    records_loaded: int = 0
    bytes_written: int = 0
    duration_ms: int = 0
    success: bool = True
    error: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityDataPipelineState(BaseModel):
    """Main state for the Security Data Pipeline agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SDPStage = SDPStage.INGEST_SOURCES

    ingested_records: list[IngestedRecord] = Field(
        default_factory=list,
    )
    transformed_records: list[TransformedRecord] = Field(
        default_factory=list,
    )
    enrichments: list[EnrichmentResult] = Field(
        default_factory=list,
    )
    quality_checks: list[QualityCheck] = Field(
        default_factory=list,
    )
    load_results: list[LoadResult] = Field(
        default_factory=list,
    )

    report: str = ""
    total_records_processed: int = 0
    enrichment_hit_rate: float = 0.0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
