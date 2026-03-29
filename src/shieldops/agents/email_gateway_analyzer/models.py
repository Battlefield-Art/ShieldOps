"""Email Gateway Analyzer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class GatewayStage(StrEnum):
    COLLECT_RECORDS = "collect_records"
    VALIDATE_AUTH = "validate_auth"
    ANALYZE_HEADERS = "analyze_headers"
    CHECK_REPUTATION = "check_reputation"
    DETECT_SPOOFING = "detect_spoofing"
    REPORT = "report"


class AuthProtocol(StrEnum):
    SPF = "spf"
    DKIM = "dkim"
    DMARC = "dmarc"
    ARC = "arc"
    BIMI = "bimi"
    MTA_STS = "mta_sts"


class ThreatLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class EmailHeader(BaseModel):
    """Parsed email header record."""

    message_id: str = ""
    sender: str = ""
    return_path: str = ""
    received_chain: list[str] = Field(default_factory=list)
    subject: str = ""
    date: str = ""
    authentication_results: str = ""
    x_mailer: str = ""
    content_type: str = ""
    has_suspicious_headers: bool = False


class SPFResult(BaseModel):
    """SPF/DKIM/DMARC validation result."""

    domain: str = ""
    protocol: AuthProtocol = AuthProtocol.SPF
    result: str = ""
    policy: str = ""
    alignment: str = ""
    record_value: str = ""
    is_valid: bool = False
    issues: list[str] = Field(default_factory=list)


class GatewayAnalyzerState(BaseModel):
    """Full state for the Email Gateway Analyzer agent."""

    request_id: str = ""
    stage: GatewayStage = GatewayStage.COLLECT_RECORDS
    tenant_id: str = ""
    domains: list[str] = Field(default_factory=list)
    dns_records: list[dict[str, Any]] = Field(default_factory=list)
    auth_results: list[dict[str, Any]] = Field(default_factory=list)
    auth_pass_rate: float = 0.0
    headers_analyzed: list[dict[str, Any]] = Field(default_factory=list)
    suspicious_headers_count: int = 0
    reputation_scores: list[dict[str, Any]] = Field(default_factory=list)
    avg_reputation: float = 0.0
    spoofing_attempts: list[dict[str, Any]] = Field(default_factory=list)
    spoofing_detected: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
