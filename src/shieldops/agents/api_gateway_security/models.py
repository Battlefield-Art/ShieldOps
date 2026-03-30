"""API Gateway Security Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AGSStage(StrEnum):
    SCAN_ENDPOINTS = "scan_endpoints"
    ANALYZE_TRAFFIC = "analyze_traffic"
    DETECT_ABUSE = "detect_abuse"
    ENFORCE_POLICIES = "enforce_policies"
    GENERATE_ALERTS = "generate_alerts"
    REPORT = "report"


class EndpointRisk(StrEnum):
    EXPOSED = "exposed"
    MISCONFIGURED = "misconfigured"
    DEPRECATED = "deprecated"
    UNAUTHENTICATED = "unauthenticated"
    RATE_LIMITED = "rate_limited"
    HEALTHY = "healthy"


class AbuseType(StrEnum):
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    SCRAPING = "scraping"
    INJECTION = "injection"
    DOS = "dos"
    ENUMERATION = "enumeration"


class APIGatewaySecurityState(BaseModel):
    request_id: str = ""
    stage: AGSStage = AGSStage.SCAN_ENDPOINTS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
