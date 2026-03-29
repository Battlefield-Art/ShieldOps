"""Shift Handoff Manager Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class HandoffStage(StrEnum):
    COLLECT_STATE = "collect_state"
    SUMMARIZE_INCIDENTS = "summarize_incidents"
    DOCUMENT_ACTIONS = "document_actions"
    BRIEF_INCOMING = "brief_incoming"
    TRANSFER = "transfer"
    REPORT = "report"


class ShiftType(StrEnum):
    DAY = "day"
    SWING = "swing"
    NIGHT = "night"
    WEEKEND = "weekend"
    HOLIDAY = "holiday"
    ON_CALL = "on_call"


class HandoffStatus(StrEnum):
    PREPARING = "preparing"
    READY = "ready"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ACKNOWLEDGED = "acknowledged"


class ShiftHandoffManagerState(BaseModel):
    request_id: str = ""
    stage: HandoffStage = HandoffStage.COLLECT_STATE
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
