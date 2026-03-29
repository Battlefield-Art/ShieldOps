"""Data Breach Responder Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ResponseStage(StrEnum):
    DETECT_BREACH = "detect_breach"
    ASSESS_SCOPE = "assess_scope"
    CONTAIN = "contain"
    NOTIFY_AUTHORITIES = "notify_authorities"
    NOTIFY_SUBJECTS = "notify_subjects"
    REPORT = "report"


class BreachType(StrEnum):
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    ACCIDENTAL_DISCLOSURE = "accidental_disclosure"
    RANSOMWARE = "ransomware"
    INSIDER = "insider"
    THIRD_PARTY = "third_party"


class NotificationStatus(StrEnum):
    PENDING = "pending"
    SENT = "sent"
    ACKNOWLEDGED = "acknowledged"
    OVERDUE = "overdue"
    EXEMPT = "exempt"


class DataBreachResponderState(BaseModel):
    request_id: str = ""
    stage: ResponseStage = ResponseStage.DETECT_BREACH
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
