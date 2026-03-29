"""Ticket Automation Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AutomationStage(StrEnum):
    CLASSIFY_EVENT = "classify_event"
    CREATE_TICKET = "create_ticket"
    ASSIGN_OWNER = "assign_owner"
    SET_SLA = "set_sla"
    TRACK = "track"
    REPORT = "report"


class TicketType(StrEnum):
    INCIDENT = "incident"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    ACCESS_REQUEST = "access_request"
    CHANGE_REQUEST = "change_request"
    INVESTIGATION = "investigation"


class SLAStatus(StrEnum):
    WITHIN_SLA = "within_sla"
    AT_RISK = "at_risk"
    BREACHED = "breached"
    PAUSED = "paused"
    RESOLVED = "resolved"


class TicketAutomationState(BaseModel):
    request_id: str = ""
    stage: AutomationStage = AutomationStage.CLASSIFY_EVENT
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
