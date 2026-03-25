"""API Security Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SecurityStage(StrEnum):
    DISCOVER_ENDPOINTS = "discover_endpoints"
    ANALYZE_TRAFFIC = "analyze_traffic"
    DETECT_VULNERABILITIES = "detect_vulnerabilities"
    DETECT_ABUSE = "detect_abuse"
    ENFORCE_POLICIES = "enforce_policies"
    REPORT = "report"


class VulnerabilityType(StrEnum):
    BOLA = "bola"
    BROKEN_AUTH = "broken_auth"
    EXCESSIVE_DATA = "excessive_data"
    RESOURCE_LACK = "resource_lack"
    FUNCTION_LEVEL_AUTH = "function_level_auth"
    MASS_ASSIGNMENT = "mass_assignment"
    SECURITY_MISCONFIG = "security_misconfig"
    INJECTION = "injection"
    IMPROPER_ASSET = "improper_asset"
    SSRF = "ssrf"


class AbuseType(StrEnum):
    CREDENTIAL_STUFFING = "credential_stuffing"
    SCRAPING = "scraping"
    ENUMERATION = "enumeration"
    RATE_ABUSE = "rate_abuse"
    DATA_HARVESTING = "data_harvesting"
    BRUTE_FORCE = "brute_force"


class APISeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class APIEndpoint(BaseModel):
    """A discovered API endpoint with traffic metadata."""

    id: str = ""
    method: str = "GET"
    path: str = ""
    service: str = ""
    auth_required: bool = True
    rate_limited: bool = False
    requests_per_day: int = 0
    avg_latency_ms: float = 0.0
    error_rate: float = 0.0
    last_scanned: float = 0.0


class APIVulnerability(BaseModel):
    """An OWASP API Top 10 vulnerability detected on an endpoint."""

    id: str = ""
    endpoint_id: str = ""
    vulnerability_type: VulnerabilityType = VulnerabilityType.SECURITY_MISCONFIG
    description: str = ""
    severity: APISeverity = APISeverity.MEDIUM
    confidence: float = 0.0
    owasp_reference: str = ""
    remediation: str = ""
    cwe_id: str = ""


class APIAbuseIncident(BaseModel):
    """An API abuse incident detected from traffic analysis."""

    id: str = ""
    endpoint_id: str = ""
    abuse_type: AbuseType = AbuseType.RATE_ABUSE
    source_ip: str = ""
    request_count: int = 0
    time_window_minutes: int = 0
    description: str = ""
    severity: APISeverity = APISeverity.MEDIUM
    blocked: bool = False


class PolicyEnforcement(BaseModel):
    """A policy enforcement action applied to an endpoint."""

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


class APISecurityState(BaseModel):
    """Main state for the API Security graph."""

    # Input
    request_id: str = ""
    stage: SecurityStage = SecurityStage.DISCOVER_ENDPOINTS
    tenant_id: str = ""
    scan_scope: list[str] = Field(default_factory=list)

    # Discovery & analysis
    discovered_endpoints: list[dict[str, Any]] = Field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    abuse_incidents: list[dict[str, Any]] = Field(default_factory=list)
    policy_enforcements: list[dict[str, Any]] = Field(default_factory=list)

    # Metadata
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
