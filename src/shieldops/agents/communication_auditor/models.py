"""Communication Auditor Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AuditStage(StrEnum):
    COLLECT_MESSAGES = "collect_messages"
    CLASSIFY = "classify"
    CHECK_COMPLIANCE = "check_compliance"
    FLAG_VIOLATIONS = "flag_violations"
    GENERATE_REPORT = "generate_report"
    REPORT = "report"


class ChannelType(StrEnum):
    SLACK = "slack"
    TEAMS = "teams"
    EMAIL = "email"
    ZOOM = "zoom"
    WEBEX = "webex"
    CUSTOM = "custom"


class ComplianceStatus(StrEnum):
    COMPLIANT = "compliant"
    VIOLATION = "violation"
    REVIEW_NEEDED = "review_needed"
    EXEMPTED = "exempted"
    PENDING = "pending"


class MessageAudit(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class RetentionPolicy(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class ComplianceViolation(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class CommunicationAuditorState(BaseModel):
    request_id: str = ""
    stage: AuditStage = AuditStage.COLLECT_MESSAGES
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
