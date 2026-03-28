"""State models for Incident Communicator Agent."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class CommStage(StrEnum):
    """Stages in the communication workflow."""

    IDENTIFY_STAKEHOLDERS = "identify_stakeholders"
    DRAFT_MESSAGES = "draft_messages"
    SELECT_CHANNELS = "select_channels"
    SEND_NOTIFICATIONS = "send_notifications"
    TRACK_ACKS = "track_acks"
    REPORT = "report"


class ChannelType(StrEnum):
    """Communication channel types."""

    SLACK = "slack"
    EMAIL = "email"
    PAGERDUTY = "pagerduty"
    SMS = "sms"
    TEAMS = "teams"
    VOICE = "voice"


class MessagePriority(StrEnum):
    """Message priority levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Notification(BaseModel):
    """A single notification record."""

    id: str = ""
    recipient: str = ""
    channel: ChannelType = ChannelType.SLACK
    priority: MessagePriority = MessagePriority.MEDIUM
    message: str = ""
    sent: bool = False
    acknowledged: bool = False


class IncidentCommunicatorState(BaseModel):
    """Full state for Incident Communicator."""

    request_id: str = ""
    stage: CommStage = CommStage.IDENTIFY_STAKEHOLDERS
    tenant_id: str = ""
    incident_id: str = ""
    notifications: list[Notification] = Field(default_factory=list)
    channels_used: list[str] = Field(default_factory=list)
    ack_count: int = 0
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
    session_start: float = 0.0
