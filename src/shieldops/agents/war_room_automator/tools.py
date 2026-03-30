"""Tool functions for the War Room Automator."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from .models import ParticipantRole, RoomType

logger = structlog.get_logger()

SEVERITY_ROOM_MAP: dict[str, RoomType] = {
    "critical": RoomType.CRITICAL_INCIDENT,
    "sev1": RoomType.CRITICAL_INCIDENT,
    "security": RoomType.SECURITY_BREACH,
    "sev2": RoomType.OUTAGE,
    "high": RoomType.OUTAGE,
    "medium": RoomType.DEGRADATION,
    "low": RoomType.DEGRADATION,
}

ROOM_ROLES: dict[RoomType, list[ParticipantRole]] = {
    RoomType.CRITICAL_INCIDENT: [
        ParticipantRole.INCIDENT_COMMANDER,
        ParticipantRole.TECH_LEAD,
        ParticipantRole.COMMUNICATOR,
        ParticipantRole.SUBJECT_EXPERT,
        ParticipantRole.SCRIBE,
    ],
    RoomType.SECURITY_BREACH: [
        ParticipantRole.INCIDENT_COMMANDER,
        ParticipantRole.TECH_LEAD,
        ParticipantRole.SUBJECT_EXPERT,
        ParticipantRole.COMMUNICATOR,
    ],
    RoomType.OUTAGE: [
        ParticipantRole.INCIDENT_COMMANDER,
        ParticipantRole.TECH_LEAD,
        ParticipantRole.SCRIBE,
    ],
    RoomType.DEGRADATION: [
        ParticipantRole.TECH_LEAD,
        ParticipantRole.SUBJECT_EXPERT,
    ],
    RoomType.DRILL: [
        ParticipantRole.INCIDENT_COMMANDER,
        ParticipantRole.OBSERVER,
    ],
    RoomType.POSTMORTEM: [
        ParticipantRole.TECH_LEAD,
        ParticipantRole.SCRIBE,
    ],
}


class WarRoomAutomatorToolkit:
    """Toolkit for war room automation workflows."""

    def __init__(
        self,
        chat_service: Any | None = None,
        oncall_service: Any | None = None,
    ) -> None:
        self._chat = chat_service
        self._oncall = oncall_service

    async def detect_incident(
        self,
        incident_id: str,
        incident_title: str,
        incident_severity: str,
        affected_services: list[str],
    ) -> dict[str, Any]:
        """Detect and classify the incident for war room."""
        sev_lower = incident_severity.lower()
        room_type = RoomType.DEGRADATION
        for key, rtype in SEVERITY_ROOM_MAP.items():
            if key in sev_lower:
                room_type = rtype
                break

        needs_room = room_type in (
            RoomType.CRITICAL_INCIDENT,
            RoomType.SECURITY_BREACH,
            RoomType.OUTAGE,
        )

        logger.info(
            "wra.detect_incident",
            room_type=room_type.value,
            needs_room=needs_room,
        )
        return {
            "id": f"wra-det-{uuid4().hex[:8]}",
            "incident_id": incident_id,
            "room_type": room_type.value,
            "needs_war_room": needs_room,
            "service_count": len(affected_services),
        }

    async def create_room(
        self,
        detection_result: dict[str, Any],
        incident_title: str,
    ) -> dict[str, Any]:
        """Create the war room channel/space."""
        room_type = detection_result.get(
            "room_type",
            "degradation",
        )
        room_id = f"wra-room-{uuid4().hex[:8]}"
        channel = f"war-room-{room_id}"

        if self._chat:
            try:
                await self._chat.create_channel(channel)
            except Exception:
                logger.warning("wra.create_room_failed")

        logger.info(
            "wra.create_room",
            room_id=room_id,
            channel=channel,
        )
        return {
            "room_id": room_id,
            "channel_name": channel,
            "room_type": room_type,
            "title": incident_title,
            "created_at": time.time(),
        }

    async def assemble_team(
        self,
        room_config: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Assemble the team for the war room."""
        rtype_val = room_config.get(
            "room_type",
            "degradation",
        )
        try:
            rtype = RoomType(rtype_val)
        except ValueError:
            rtype = RoomType.DEGRADATION

        roles = ROOM_ROLES.get(
            rtype,
            [
                ParticipantRole.TECH_LEAD,
            ],
        )
        roster: list[dict[str, Any]] = []
        for role in roles:
            member = {
                "id": f"wra-mbr-{uuid4().hex[:8]}",
                "role": role.value,
                "status": "invited",
                "joined_at": None,
            }
            roster.append(member)

        logger.info(
            "wra.assemble_team",
            team_size=len(roster),
        )
        return roster

    async def share_context(
        self,
        room_config: dict[str, Any],
        incident_description: str,
        affected_services: list[str],
    ) -> dict[str, Any]:
        """Share incident context in the war room."""
        logger.info("wra.share_context")
        return {
            "id": f"wra-ctx-{uuid4().hex[:8]}",
            "room_id": room_config.get("room_id", ""),
            "incident_summary": incident_description[:500],
            "affected_services": affected_services,
            "runbooks_linked": len(affected_services),
            "dashboards_linked": min(
                len(affected_services),
                3,
            ),
            "shared_at": time.time(),
        }

    async def coordinate_actions(
        self,
        team_roster: list[dict[str, Any]],
        shared_context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Coordinate action items in the war room."""
        actions: list[dict[str, Any]] = []
        default_actions = [
            "Confirm blast radius",
            "Check recent deployments",
            "Monitor error rates",
            "Prepare customer comms",
            "Document timeline",
        ]
        for i, action in enumerate(default_actions):
            owner = team_roster[i % len(team_roster)] if team_roster else {"role": "unassigned"}
            actions.append(
                {
                    "id": f"wra-act-{uuid4().hex[:8]}",
                    "action": action,
                    "owner_role": owner.get(
                        "role",
                        "unassigned",
                    ),
                    "status": "pending",
                    "priority": "high" if i < 2 else "medium",
                }
            )

        logger.info(
            "wra.coordinate_actions",
            action_count=len(actions),
        )
        return actions
