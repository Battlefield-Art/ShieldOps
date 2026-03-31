"""State models for the Security Lake Manager Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class LakeStage(StrEnum):
    """Stages of the security data lake management workflow."""

    DISCOVER_SOURCES = "discover_sources"
    INGEST_DATA = "ingest_data"
    NORMALIZE_SCHEMA = "normalize_schema"
    OPTIMIZE_STORAGE = "optimize_storage"
    QUERY_ANALYTICS = "query_analytics"
    REPORT = "report"


class StorageTier(StrEnum):
    """Tiered storage classifications."""

    HOT = "hot"
    WARM = "warm"
    COLD = "cold"
    FROZEN = "frozen"
    ARCHIVE = "archive"


class SchemaFormat(StrEnum):
    """Schema normalization formats."""

    OCSF = "ocsf"
    ECS = "ecs"
    CEF = "cef"
    LEEF = "leef"
    RAW = "raw"
    CUSTOM = "custom"


class DataSource(BaseModel):
    """A discovered data source feeding the security lake."""

    id: str = ""
    name: str = ""
    source_type: str = ""
    connector: str = ""
    format: SchemaFormat = SchemaFormat.RAW
    events_per_day: int = 0
    avg_event_size_bytes: int = 0
    active: bool = True


class IngestionRecord(BaseModel):
    """Record of a data ingestion batch."""

    id: str = ""
    source_id: str = ""
    records_ingested: int = 0
    bytes_ingested: int = 0
    errors: int = 0
    latency_ms: float = 0.0
    normalized: bool = False


class StorageOptimization(BaseModel):
    """Storage optimization recommendation or action."""

    id: str = ""
    partition_key: str = ""
    current_tier: StorageTier = StorageTier.HOT
    recommended_tier: StorageTier = StorageTier.WARM
    current_cost_daily: float = 0.0
    projected_cost_daily: float = 0.0
    savings_pct: float = 0.0
    applied: bool = False


class AnalyticsResult(BaseModel):
    """Result from a security lake analytics query."""

    id: str = ""
    query_name: str = ""
    records_scanned: int = 0
    records_matched: int = 0
    execution_time_ms: float = 0.0
    findings: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: int = 0
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityLakeState(BaseModel):
    """Full state of a security lake management workflow."""

    # Identity
    request_id: str = ""
    stage: LakeStage = LakeStage.DISCOVER_SOURCES
    tenant_id: str = ""

    # Data
    data_sources: list[dict[str, Any]] = Field(default_factory=list)
    ingestion_records: list[dict[str, Any]] = Field(default_factory=list)
    schema_mappings: list[dict[str, Any]] = Field(default_factory=list)
    storage_optimizations: list[dict[str, Any]] = Field(default_factory=list)
    analytics_results: list[dict[str, Any]] = Field(default_factory=list)

    # Metrics
    total_sources: int = 0
    total_daily_volume_gb: float = 0.0
    cost_savings_pct: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Tracking
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
