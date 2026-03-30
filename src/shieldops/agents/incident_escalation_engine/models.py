"""State models for the Incident Escalation Engine Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IEEStage(StrEnum):
    """Stages in the escalation workflow."""

    ASSESS_SEVERITY = "assess_severity"
    EVALUATE_IMPACT = "evaluate_impact"
    DETERMINE_ESCALATION = "determine_escalation"
    NOTIFY_RESPONDERS = "notify_responders"
    TRACK_RESPONSE = "track_response"
    REPORT = "report"


class EscalationTier(StrEnum):
    """Escalation tier levels."""

    TIER_1 = "tier_1"
    TIER_2 = "tier_2"
    TIER_3 = "tier_3"
    EXECUTIVE = "executive"
    EXTERNAL = "external"
    REGULATORY = "regulatory"


class UrgencyLevel(StrEnum):
    """Urgency classification for incidents."""

    IMMEDIATE = "immediate"
    URGENT = "urgent"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentEscalationEngineState(BaseModel):
    """Full state for the escalation engine workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: IEEStage = IEEStage.ASSESS_SEVERITY

    incident_id: str = ""
    incident_title: str = ""
    incident_description: str = ""
    severity_raw: str = ""
    affected_services: list[str] = Field(
        default_factory=list,
    )
    alert_count: int = 0

    severity_assessment: dict[str, Any] = Field(
        default_factory=dict,
    )
    impact_evaluation: dict[str, Any] = Field(
        default_factory=dict,
    )
    escalation_decision: dict[str, Any] = Field(
        default_factory=dict,
    )
    notifications_sent: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    response_tracking: dict[str, Any] = Field(
        default_factory=dict,
    )
    stats: dict[str, Any] = Field(
        default_factory=dict,
    )
    reasoning_chain: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    current_step: str = ""
    error: str = ""
