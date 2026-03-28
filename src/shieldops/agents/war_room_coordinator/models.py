"""State models for the War Room Coordinator Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class WarRoomStage(StrEnum):
    """Stages in the war room coordination workflow."""

    OPEN_WAR_ROOM = "open_war_room"
    ASSIGN_ROLES = "assign_roles"
    TRACK_ACTIONS = "track_actions"
    MAINTAIN_TIMELINE = "maintain_timeline"
    COORDINATE_COMMS = "coordinate_comms"
    REPORT = "report"


class TeamRole(StrEnum):
    """Roles within the war room."""

    INCIDENT_COMMANDER = "incident_commander"
    TECHNICAL_LEAD = "technical_lead"
    COMMUNICATIONS = "communications"
    LEGAL = "legal"
    EXECUTIVE = "executive"
    FORENSICS = "forensics"


class ActionStatus(StrEnum):
    """Status of a war room action item."""

    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    ESCALATED = "escalated"


class WarRoom(BaseModel):
    """War room instance."""

    id: str = ""
    incident_id: str = ""
    name: str = ""
    channel: str = ""
    bridge_url: str = ""
    opened_at: float = 0.0
    severity: str = "high"
    status: str = "active"


class RoleAssignment(BaseModel):
    """Assignment of a team member to a war room role."""

    id: str = ""
    role: TeamRole = TeamRole.TECHNICAL_LEAD
    assignee: str = ""
    team: str = ""
    contact: str = ""
    accepted: bool = False
    assigned_at: float = 0.0


class ActionItem(BaseModel):
    """Action item tracked in the war room."""

    id: str = ""
    title: str = ""
    assignee: str = ""
    role: TeamRole = TeamRole.TECHNICAL_LEAD
    status: ActionStatus = ActionStatus.ASSIGNED
    priority: str = "high"
    due_by: str = ""
    notes: str = ""
    created_at: float = 0.0
    completed_at: float = 0.0


class TimelineEntry(BaseModel):
    """Entry in the incident timeline."""

    id: str = ""
    timestamp: float = 0.0
    event: str = ""
    actor: str = ""
    category: str = ""
    impact: str = ""


class CommunicationLog(BaseModel):
    """Log of communications during the war room."""

    id: str = ""
    channel: str = ""
    sender: str = ""
    message: str = ""
    timestamp: float = 0.0
    audience: str = ""
    message_type: str = "update"


class WarRoomCoordinatorState(BaseModel):
    """Full state for the War Room Coordinator workflow."""

    request_id: str = ""
    stage: WarRoomStage = WarRoomStage.OPEN_WAR_ROOM
    tenant_id: str = ""

    # Input
    incident_id: str = ""
    incident_details: dict[str, Any] = Field(default_factory=dict)

    # War room
    war_room: WarRoom = Field(default_factory=WarRoom)

    # Roles
    role_assignments: list[RoleAssignment] = Field(default_factory=list)

    # Actions
    action_items: list[ActionItem] = Field(default_factory=list)

    # Timeline
    timeline: list[TimelineEntry] = Field(default_factory=list)

    # Communications
    comms_log: list[CommunicationLog] = Field(default_factory=list)

    # Stats & reporting
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)

    # Workflow metadata
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: int = 0
    error: str = ""
