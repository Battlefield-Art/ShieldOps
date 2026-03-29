"""Just In Time Access Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class JITStage(StrEnum):
    RECEIVE_REQUEST = "receive_request"
    EVALUATE_POLICY = "evaluate_policy"
    PROVISION_ACCESS = "provision_access"
    MONITOR_SESSION = "monitor_session"
    REVOKE_ACCESS = "revoke_access"
    REPORT = "report"


class AccessType(StrEnum):
    ADMIN = "admin"
    DATABASE = "database"
    CLOUD_CONSOLE = "cloud_console"
    SSH = "ssh"
    API = "api"
    FILE_SHARE = "file_share"


class RequestStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    ACTIVE = "active"
    EXPIRED = "expired"
    DENIED = "denied"
    REVOKED = "revoked"


class JustInTimeAccessState(BaseModel):
    request_id: str = ""
    stage: JITStage = JITStage.RECEIVE_REQUEST
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
