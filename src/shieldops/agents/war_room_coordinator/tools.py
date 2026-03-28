"""Tool functions for the War Room Coordinator Agent."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.war_room_coordinator.models import (
    ActionItem,
    ActionStatus,
    CommunicationLog,
    RoleAssignment,
    TeamRole,
    TimelineEntry,
    WarRoom,
)

logger = structlog.get_logger()

# Default role assignments by severity
ROLE_TEMPLATES: dict[str, list[TeamRole]] = {
    "critical": [
        TeamRole.INCIDENT_COMMANDER,
        TeamRole.TECHNICAL_LEAD,
        TeamRole.COMMUNICATIONS,
        TeamRole.LEGAL,
        TeamRole.EXECUTIVE,
        TeamRole.FORENSICS,
    ],
    "high": [
        TeamRole.INCIDENT_COMMANDER,
        TeamRole.TECHNICAL_LEAD,
        TeamRole.COMMUNICATIONS,
        TeamRole.FORENSICS,
    ],
    "medium": [
        TeamRole.INCIDENT_COMMANDER,
        TeamRole.TECHNICAL_LEAD,
    ],
    "low": [
        TeamRole.TECHNICAL_LEAD,
    ],
}

# Default on-call roster (simulated)
DEFAULT_ROSTER: dict[TeamRole, dict[str, str]] = {
    TeamRole.INCIDENT_COMMANDER: {
        "assignee": "ic-oncall",
        "team": "sre-leadership",
        "contact": "ic@example.com",
    },
    TeamRole.TECHNICAL_LEAD: {
        "assignee": "tech-oncall",
        "team": "platform-sre",
        "contact": "tech@example.com",
    },
    TeamRole.COMMUNICATIONS: {
        "assignee": "comms-oncall",
        "team": "communications",
        "contact": "comms@example.com",
    },
    TeamRole.LEGAL: {
        "assignee": "legal-oncall",
        "team": "legal",
        "contact": "legal@example.com",
    },
    TeamRole.EXECUTIVE: {
        "assignee": "vp-engineering",
        "team": "executive",
        "contact": "exec@example.com",
    },
    TeamRole.FORENSICS: {
        "assignee": "forensics-oncall",
        "team": "security",
        "contact": "forensics@example.com",
    },
}


class WarRoomCoordinatorToolkit:
    """Toolkit for war room coordination."""

    def __init__(
        self,
        roster_service: Any | None = None,
        comms_service: Any | None = None,
    ) -> None:
        self._roster_service = roster_service
        self._comms_service = comms_service

    async def open_war_room(
        self,
        incident_id: str,
        incident_details: dict[str, Any],
    ) -> WarRoom:
        """Open a new virtual war room."""
        now = time.time()
        severity = incident_details.get("severity", "high")
        title = incident_details.get("title", "Untitled Incident")

        war_room = WarRoom(
            id=f"wr-{uuid4().hex[:12]}",
            incident_id=incident_id,
            name=f"War Room: {title}",
            channel=f"#war-room-{incident_id[:8]}",
            bridge_url=(f"https://meet.example.com/war-room-{incident_id[:8]}"),
            opened_at=now,
            severity=severity,
            status="active",
        )

        logger.info(
            "war_room.opened",
            war_room_id=war_room.id,
            incident_id=incident_id,
            severity=severity,
        )

        return war_room

    async def assign_roles(
        self,
        war_room: WarRoom,
        incident_details: dict[str, Any],
    ) -> list[RoleAssignment]:
        """Assign roles based on incident severity."""
        severity = war_room.severity
        roles = ROLE_TEMPLATES.get(severity, ROLE_TEMPLATES["medium"])
        now = time.time()

        assignments: list[RoleAssignment] = []
        for role in roles:
            roster = DEFAULT_ROSTER.get(role, {})

            if self._roster_service is not None:
                try:
                    roster = await self._roster_service.get_oncall(role.value)
                except Exception:
                    logger.debug(
                        "roster_lookup_failed",
                        role=role.value,
                    )

            assignments.append(
                RoleAssignment(
                    id=f"ra-{uuid4().hex[:12]}",
                    role=role,
                    assignee=roster.get("assignee", "unassigned"),
                    team=roster.get("team", ""),
                    contact=roster.get("contact", ""),
                    accepted=False,
                    assigned_at=now,
                )
            )

        logger.info(
            "war_room.roles_assigned",
            war_room_id=war_room.id,
            roles=len(assignments),
        )

        return assignments

    async def generate_actions(
        self,
        war_room: WarRoom,
        role_assignments: list[RoleAssignment],
        incident_details: dict[str, Any],
    ) -> list[ActionItem]:
        """Generate initial action items for the team."""
        now = time.time()
        actions: list[ActionItem] = []

        # Default actions per role
        role_actions: dict[TeamRole, list[str]] = {
            TeamRole.INCIDENT_COMMANDER: [
                "Confirm severity and scope",
                "Set communication cadence",
                "Authorize containment actions",
            ],
            TeamRole.TECHNICAL_LEAD: [
                "Identify affected systems",
                "Begin root cause analysis",
                "Implement containment measures",
            ],
            TeamRole.COMMUNICATIONS: [
                "Draft initial stakeholder update",
                "Notify affected customers",
            ],
            TeamRole.FORENSICS: [
                "Preserve evidence",
                "Begin forensic analysis",
            ],
            TeamRole.LEGAL: [
                "Assess regulatory obligations",
            ],
            TeamRole.EXECUTIVE: [
                "Standby for escalation decisions",
            ],
        }

        for assignment in role_assignments:
            role_tasks = role_actions.get(assignment.role, [])
            for task in role_tasks:
                actions.append(
                    ActionItem(
                        id=f"act-{uuid4().hex[:12]}",
                        title=task,
                        assignee=assignment.assignee,
                        role=assignment.role,
                        status=ActionStatus.ASSIGNED,
                        priority="high",
                        due_by="",
                        notes="",
                        created_at=now,
                    )
                )

        logger.info(
            "war_room.actions_generated",
            war_room_id=war_room.id,
            action_count=len(actions),
        )

        return actions

    async def build_timeline(
        self,
        war_room: WarRoom,
        actions: list[ActionItem],
        incident_details: dict[str, Any],
    ) -> list[TimelineEntry]:
        """Build an incident timeline."""
        entries: list[TimelineEntry] = []

        entries.append(
            TimelineEntry(
                id=f"tl-{uuid4().hex[:12]}",
                timestamp=war_room.opened_at,
                event="War room opened",
                actor="system",
                category="coordination",
                impact="War room activated",
            )
        )

        # Add action assignments to timeline
        for action in actions:
            entries.append(
                TimelineEntry(
                    id=f"tl-{uuid4().hex[:12]}",
                    timestamp=action.created_at,
                    event=(f"Action assigned: {action.title}"),
                    actor=action.assignee,
                    category="action",
                    impact="",
                )
            )

        logger.info(
            "war_room.timeline_built",
            war_room_id=war_room.id,
            entries=len(entries),
        )

        return entries

    async def send_comms(
        self,
        war_room: WarRoom,
        message: str,
        audience: str,
    ) -> CommunicationLog:
        """Send a communication from the war room."""
        now = time.time()

        if self._comms_service is not None:
            try:
                await self._comms_service.send(
                    channel=war_room.channel,
                    message=message,
                )
            except Exception:
                logger.debug(
                    "comms_send_failed",
                    war_room_id=war_room.id,
                )

        log = CommunicationLog(
            id=f"comm-{uuid4().hex[:12]}",
            channel=war_room.channel,
            sender="war_room_coordinator",
            message=message,
            timestamp=now,
            audience=audience,
            message_type="update",
        )

        logger.info(
            "war_room.comms_sent",
            war_room_id=war_room.id,
            audience=audience,
        )

        return log
