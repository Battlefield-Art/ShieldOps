"""API Gateway Security Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AGSStage(StrEnum):
    DISCOVER_APIS = "discover_apis"
    ANALYZE_AUTH = "analyze_auth"
    SCAN_ENDPOINTS = "scan_endpoints"
    DETECT_ABUSE = "detect_abuse"
    ENFORCE_POLICIES = "enforce_policies"
    REPORT = "report"


class APIRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AuthType(StrEnum):
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    MTLS = "mtls"
    BASIC = "basic"
    NONE = "none"


class APIEndpoint(BaseModel):
    """A discovered API gateway endpoint with configuration."""

    id: str = ""
    method: str = "GET"
    path: str = ""
    gateway_id: str = ""
    service_backend: str = ""
    auth_type: AuthType = AuthType.NONE
    rate_limit_rpm: int = 0
    rate_limit_enabled: bool = False
    input_validation_enabled: bool = False
    cors_enabled: bool = False
    tls_version: str = ""
    requests_per_day: int = 0
    avg_latency_ms: float = 0.0
    error_rate_pct: float = 0.0
    last_seen: float = 0.0


class AuthAnalysis(BaseModel):
    """Authentication and authorization analysis."""

    id: str = ""
    endpoint_id: str = ""
    auth_type: AuthType = AuthType.NONE
    auth_strength: str = ""
    risk: APIRisk = APIRisk.MEDIUM
    issues: list[str] = Field(default_factory=list)
    token_expiry_minutes: int = 0
    scopes_enforced: bool = False
    mfa_required: bool = False
    recommendation: str = ""


class EndpointScan(BaseModel):
    """Input validation and configuration scan result."""

    id: str = ""
    endpoint_id: str = ""
    risk: APIRisk = APIRisk.MEDIUM
    description: str = ""
    category: str = ""
    input_validation_gaps: list[str] = Field(
        default_factory=list,
    )
    missing_headers: list[str] = Field(default_factory=list)
    schema_violations: list[str] = Field(
        default_factory=list,
    )
    confidence: float = 0.0
    remediation: str = ""


class AbuseDetection(BaseModel):
    """A detected API abuse pattern from traffic analysis."""

    id: str = ""
    endpoint_id: str = ""
    abuse_type: str = ""
    source_ip: str = ""
    request_count: int = 0
    time_window_minutes: int = 0
    risk: APIRisk = APIRisk.MEDIUM
    description: str = ""
    blocked: bool = False


class PolicyEnforcement(BaseModel):
    """A policy enforcement action applied to the gateway."""

    id: str = ""
    endpoint_id: str = ""
    policy_name: str = ""
    action: str = ""
    description: str = ""
    enforced_at: float = 0.0
    success: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class APIGatewaySecurityState(BaseModel):
    """Main state for the API Gateway Security graph."""

    # Input
    request_id: str = ""
    stage: AGSStage = AGSStage.DISCOVER_APIS
    tenant_id: str = ""
    gateway_ids: list[str] = Field(default_factory=list)

    # Pipeline data
    discovered_endpoints: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    auth_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    endpoint_scans: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    abuse_detections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    policy_enforcements: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metadata
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
