"""Data Lineage Tracker Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TrackingStage(StrEnum):
    DISCOVER_SOURCES = "discover_sources"
    MAP_TRANSFORMATIONS = "map_transformations"
    TRACE_LINEAGE = "trace_lineage"
    DETECT_ANOMALIES = "detect_anomalies"
    VALIDATE = "validate"
    REPORT = "report"


class DataStage(StrEnum):
    INGESTION = "ingestion"
    TRANSFORMATION = "transformation"
    STORAGE = "storage"
    PROCESSING = "processing"
    CONSUMPTION = "consumption"
    ARCHIVAL = "archival"


class LineageStatus(StrEnum):
    VERIFIED = "verified"
    PARTIAL = "partial"
    BROKEN = "broken"
    UNKNOWN = "unknown"
    DEPRECATED = "deprecated"


class DataLineageTrackerState(BaseModel):
    request_id: str = ""
    stage: TrackingStage = TrackingStage.DISCOVER_SOURCES
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
