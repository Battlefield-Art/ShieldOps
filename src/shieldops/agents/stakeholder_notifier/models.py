"""State models for the Stakeholder Notifier Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SNStage(StrEnum):
    """Stages in the notification workflow."""

    IDENTIFY_STAKEHOLDERS = "identify_stakeholders"
    ASSESS_IMPACT = "assess_impact"
    COMPOSE_MESSAGE = "compose_message"
    SELECT_CHANNELS = "select_channels"
    DELIVER_NOTIFICATION = "deliver_notification"
    REPORT = "report"


class StakeholderGroup(StrEnum):
    """Stakeholder group classification."""

    ENGINEERING = "engineering"
    MANAGEMENT = "management"
    CUSTOMERS = "customers"
    PARTNERS = "partners"
    REGULATORS = "regulators"
    MEDIA = "media"


class NotificationPriority(StrEnum):
    """Notification priority levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class StakeholderNotifierState(BaseModel):
    """Full state for the stakeholder notifier workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SNStage = SNStage.IDENTIFY_STAKEHOLDERS

    incident_id: str = ""
    incident_title: str = ""
    incident_severity: str = ""
    incident_description: str = ""
    affected_services: list[str] = Field(
        default_factory=list,
    )

    stakeholders: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    impact_assessment: dict[str, Any] = Field(
        default_factory=dict,
    )
    composed_messages: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    selected_channels: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    delivery_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    stats: dict[str, Any] = Field(
        default_factory=dict,
    )
    reasoning_chain: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    current_step: str = ""
    error: str = ""
