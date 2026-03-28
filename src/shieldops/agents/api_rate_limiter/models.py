"""API Rate Limiter — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RateLimitStage(StrEnum):
    INGEST = "ingest"
    PROFILE = "profile"
    DETECT = "detect"
    CLASSIFY = "classify"
    ENFORCE = "enforce"
    REPORT = "report"


class AbusePattern(StrEnum):
    CREDENTIAL_STUFFING = "credential_stuffing"
    API_SCRAPING = "api_scraping"
    BRUTE_FORCE = "brute_force"
    ENUMERATION = "enumeration"
    DISTRIBUTED_ATTACK = "distributed_attack"
    SLOWLORIS = "slowloris"
    NORMAL = "normal"


class ActionType(StrEnum):
    ALLOW = "allow"
    THROTTLE = "throttle"
    BLOCK = "block"
    CHALLENGE = "challenge"
    SHADOW_BAN = "shadow_ban"
    ALERT = "alert"


class ClientRequest(BaseModel):
    """A single API request from a client."""

    client_id: str = ""
    ip_address: str = ""
    endpoint: str = ""
    method: str = "GET"
    status_code: int = 200
    timestamp: float = 0.0
    user_agent: str = ""
    response_time_ms: float = 0.0
    payload_size_bytes: int = 0
    auth_token_hash: str = ""
    geo_country: str = ""


class AbuseDetection(BaseModel):
    """A detected abuse pattern for a client."""

    client_id: str = ""
    pattern: AbusePattern = AbusePattern.NORMAL
    confidence: float = 0.0
    severity: str = "low"
    evidence: dict[str, Any] = Field(default_factory=dict)
    description: str = ""
    first_seen: float = 0.0
    request_count: int = 0


class RateLimitRule(BaseModel):
    """An adaptive rate limit rule for a client or endpoint."""

    rule_id: str = ""
    client_id: str = ""
    endpoint_pattern: str = "*"
    requests_per_minute: int = 60
    burst_limit: int = 100
    action: ActionType = ActionType.THROTTLE
    reason: str = ""
    ttl_seconds: int = 3600
    adaptive: bool = True


class EnforcementAction(BaseModel):
    """An enforcement action taken against a client."""

    client_id: str = ""
    action: ActionType = ActionType.ALLOW
    rule_id: str = ""
    reason: str = ""
    timestamp: float = 0.0
    duration_seconds: int = 0


class ClientProfile(BaseModel):
    """Behavioral profile of an API client."""

    client_id: str = ""
    total_requests: int = 0
    requests_per_minute: float = 0.0
    unique_endpoints: int = 0
    error_rate: float = 0.0
    avg_response_time_ms: float = 0.0
    auth_failure_count: int = 0
    distinct_ips: int = 0
    geo_countries: list[str] = Field(default_factory=list)
    risk_score: float = 0.0


class APIRateLimiterState(BaseModel):
    """Main state for the API Rate Limiter graph."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: RateLimitStage = RateLimitStage.INGEST
    time_window_minutes: int = 5
    raw_requests: list[dict[str, Any]] = Field(default_factory=list)

    # Profiling
    client_profiles: list[dict[str, Any]] = Field(default_factory=list)
    endpoint_stats: dict[str, Any] = Field(default_factory=dict)

    # Detection
    abuse_detections: list[dict[str, Any]] = Field(default_factory=list)
    threat_score: float = 0.0

    # Enforcement
    rate_limit_rules: list[dict[str, Any]] = Field(default_factory=list)
    enforcement_actions: list[dict[str, Any]] = Field(default_factory=list)
    blocked_clients: list[str] = Field(default_factory=list)
    throttled_clients: list[str] = Field(default_factory=list)

    # Report
    summary: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
