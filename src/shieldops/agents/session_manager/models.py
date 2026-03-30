"""Session Manager Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SMStage(StrEnum):
    DISCOVER_SESSIONS = "discover_sessions"
    ANALYZE_PATTERNS = "analyze_patterns"
    DETECT_HIJACKING = "detect_hijacking"
    ENFORCE_TIMEOUTS = "enforce_timeouts"
    REVOKE_SUSPICIOUS = "revoke_suspicious"
    REPORT = "report"


class SessionType(StrEnum):
    WEB = "web"
    API = "api"
    MOBILE = "mobile"
    SERVICE_ACCOUNT = "service_account"
    FEDERATED = "federated"
    IOT = "iot"


class SessionRisk(StrEnum):
    COMPROMISED = "compromised"
    SUSPICIOUS = "suspicious"
    ANOMALOUS = "anomalous"
    NORMAL = "normal"
    TRUSTED = "trusted"
    UNKNOWN = "unknown"


class SessionManagerState(BaseModel):
    request_id: str = ""
    stage: SMStage = SMStage.DISCOVER_SESSIONS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
