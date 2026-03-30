"""State models for the War Room Automator Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class WRAStage(StrEnum):
    """Stages in the war room workflow."""

    DETECT_INCIDENT = "detect_incident"
    CREATE_ROOM = "create_room"
    ASSEMBLE_TEAM = "assemble_team"
    SHARE_CONTEXT = "share_context"
    COORDINATE_ACTIONS = "coordinate_actions"
    REPORT = "report"


class RoomType(StrEnum):
    """War room type classification."""

    CRITICAL_INCIDENT = "critical_incident"
    SECURITY_BREACH = "security_breach"
    OUTAGE = "outage"
    DEGRADATION = "degradation"
    DRILL = "drill"
    POSTMORTEM = "postmortem"


class ParticipantRole(StrEnum):
    """Participant roles in the war room."""

    INCIDENT_COMMANDER = "incident_commander"
    TECH_LEAD = "tech_lead"
    COMMUNICATOR = "communicator"
    SUBJECT_EXPERT = "subject_expert"
    OBSERVER = "observer"
    SCRIBE = "scribe"


class WarRoomAutomatorState(BaseModel):
    """Full state for the war room automator workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: WRAStage = WRAStage.DETECT_INCIDENT

    incident_id: str = ""
    incident_title: str = ""
    incident_severity: str = ""
    incident_description: str = ""
    affected_services: list[str] = Field(
        default_factory=list,
    )

    detection_result: dict[str, Any] = Field(
        default_factory=dict,
    )
    room_config: dict[str, Any] = Field(
        default_factory=dict,
    )
    team_roster: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    shared_context: dict[str, Any] = Field(
        default_factory=dict,
    )
    action_items: list[dict[str, Any]] = Field(
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
