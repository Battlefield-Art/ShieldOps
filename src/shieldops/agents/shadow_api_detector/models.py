"""Shadow API Detector Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SADStage(StrEnum):
    DISCOVER_TRAFFIC = "discover_traffic"
    ANALYZE_ENDPOINTS = "analyze_endpoints"
    DETECT_SHADOW = "detect_shadow"
    CLASSIFY_RISK = "classify_risk"
    DOCUMENT = "document"
    REPORT = "report"


class APIRiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class APICategory(StrEnum):
    INTERNAL = "internal"
    PARTNER = "partner"
    PUBLIC = "public"
    SHADOW = "shadow"
    DEPRECATED = "deprecated"
    UNDOCUMENTED = "undocumented"


class TrafficRecord(BaseModel):
    """A captured API traffic record."""

    id: str = ""
    timestamp: str = ""
    method: str = "GET"
    path: str = ""
    host: str = ""
    source_ip: str = ""
    status_code: int = 200
    latency_ms: float = 0.0
    request_bytes: int = 0
    response_bytes: int = 0
    authenticated: bool = False


class EndpointProfile(BaseModel):
    """Profile of a discovered API endpoint."""

    id: str = ""
    method: str = "GET"
    path: str = ""
    host: str = ""
    request_count: int = 0
    unique_callers: int = 0
    avg_latency_ms: float = 0.0
    error_rate: float = 0.0
    has_auth: bool = False
    documented: bool = False


class ShadowAPI(BaseModel):
    """A detected shadow or undocumented API."""

    id: str = ""
    method: str = "GET"
    path: str = ""
    host: str = ""
    category: APICategory = APICategory.SHADOW
    risk_level: APIRiskLevel = APIRiskLevel.HIGH
    evidence: list[str] = Field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    request_count: int = 0


class RiskClassification(BaseModel):
    """Risk classification for a shadow API."""

    id: str = ""
    api_id: str = ""
    risk_level: APIRiskLevel = APIRiskLevel.MEDIUM
    risk_factors: list[str] = Field(default_factory=list)
    data_exposure: bool = False
    pii_detected: bool = False
    compliance_impact: list[str] = Field(default_factory=list)


class DocumentationEntry(BaseModel):
    """Auto-generated documentation for a discovered API."""

    id: str = ""
    api_id: str = ""
    method: str = "GET"
    path: str = ""
    description: str = ""
    parameters: list[str] = Field(default_factory=list)
    response_schema: str = ""
    status: str = "draft"


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ShadowAPIDetectorState(BaseModel):
    """Main state for the Shadow API Detector agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SADStage = SADStage.DISCOVER_TRAFFIC

    traffic_records: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    endpoint_profiles: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    shadow_apis: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    documentation_entries: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    report: str = ""
    total_endpoints_scanned: int = 0
    shadow_apis_found: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
