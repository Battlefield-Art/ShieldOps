"""Node implementations for the War Room Coordinator Agent."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.war_room_coordinator.models import (
    WarRoomStage,
)
from shieldops.agents.war_room_coordinator.prompts import (
    SYSTEM_ASSIGN_ROLES,
    SYSTEM_COORDINATE_COMMS,
    SYSTEM_REPORT,
    SYSTEM_TRACK_ACTIONS,
    ActionPlanOutput,
    CommsOutput,
    ReportOutput,
    RoleAssignmentOutput,
)
from shieldops.agents.war_room_coordinator.tools import (
    WarRoomCoordinatorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: WarRoomCoordinatorToolkit | None = None


def set_toolkit(
    toolkit: WarRoomCoordinatorToolkit,
) -> None:
    """Set the global toolkit instance."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> WarRoomCoordinatorToolkit:
    if _toolkit is None:
        return WarRoomCoordinatorToolkit()
    return _toolkit


async def open_war_room(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Open a virtual war room for the incident."""
    start = time.time()
    toolkit = _get_toolkit()

    incident_id = state.get("incident_id", "")
    incident_details = state.get("incident_details", {})

    war_room = await toolkit.open_war_room(
        incident_id=incident_id,
        incident_details=incident_details,
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])

    return {
        "war_room": war_room,
        "stage": WarRoomStage.OPEN_WAR_ROOM,
        "current_step": "open_war_room",
        "session_start": start,
        "reasoning_chain": [
            *chain,
            (
                f"[open_war_room] Opened war room "
                f"{war_room.id} for incident "
                f"{incident_id} "
                f"(severity={war_room.severity}) "
                f"({elapsed}ms)"
            ),
        ],
    }


async def assign_roles(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Assign team roles based on incident severity."""
    start = time.time()
    toolkit = _get_toolkit()

    war_room = state.get("war_room")
    incident_details = state.get("incident_details", {})

    assignments = await toolkit.assign_roles(
        war_room=war_room,
        incident_details=incident_details,
    )

    # LLM enhancement for role reasoning
    try:
        result = await llm_structured(
            system_prompt=SYSTEM_ASSIGN_ROLES,
            user_prompt=(
                f"Incident: "
                f"{incident_details.get('title', 'N/A')}\n"
                f"Severity: {war_room.severity}\n"
                f"Type: "
                f"{incident_details.get('type', 'unknown')}\n"
                f"Roles assigned: "
                f"{len(assignments)}"
            ),
            output_schema=RoleAssignmentOutput,
        )
        _ = result.reasoning
    except Exception:
        logger.warning(
            "war_room_coordinator.llm_roles_fallback",
        )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])

    return {
        "role_assignments": assignments,
        "stage": WarRoomStage.ASSIGN_ROLES,
        "current_step": "assign_roles",
        "reasoning_chain": [
            *chain,
            (f"[assign_roles] Assigned {len(assignments)} roles ({elapsed}ms)"),
        ],
    }


async def track_actions(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate and track action items for the team."""
    start = time.time()
    toolkit = _get_toolkit()

    war_room = state.get("war_room")
    role_assignments = state.get("role_assignments", [])
    incident_details = state.get("incident_details", {})

    actions = await toolkit.generate_actions(
        war_room=war_room,
        role_assignments=role_assignments,
        incident_details=incident_details,
    )

    # LLM enhancement for action prioritization
    try:
        result = await llm_structured(
            system_prompt=SYSTEM_TRACK_ACTIONS,
            user_prompt=(
                f"Incident: "
                f"{incident_details.get('title', 'N/A')}\n"
                f"Severity: {war_room.severity}\n"
                f"Roles: {len(role_assignments)}\n"
                f"Actions generated: {len(actions)}"
            ),
            output_schema=ActionPlanOutput,
        )
        _ = result.critical_path
    except Exception:
        logger.warning(
            "war_room_coordinator.llm_actions_fallback",
        )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])

    return {
        "action_items": actions,
        "stage": WarRoomStage.TRACK_ACTIONS,
        "current_step": "track_actions",
        "reasoning_chain": [
            *chain,
            (f"[track_actions] Generated {len(actions)} action items ({elapsed}ms)"),
        ],
    }


async def maintain_timeline(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Build and maintain the incident timeline."""
    start = time.time()
    toolkit = _get_toolkit()

    war_room = state.get("war_room")
    actions = state.get("action_items", [])
    incident_details = state.get("incident_details", {})

    timeline = await toolkit.build_timeline(
        war_room=war_room,
        actions=actions,
        incident_details=incident_details,
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])

    return {
        "timeline": timeline,
        "stage": WarRoomStage.MAINTAIN_TIMELINE,
        "current_step": "maintain_timeline",
        "reasoning_chain": [
            *chain,
            (f"[maintain_timeline] Built timeline with {len(timeline)} entries ({elapsed}ms)"),
        ],
    }


async def coordinate_comms(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Coordinate war room communications."""
    start = time.time()
    toolkit = _get_toolkit()

    war_room = state.get("war_room")
    incident_details = state.get("incident_details", {})
    actions = state.get("action_items", [])
    timeline = state.get("timeline", [])

    # Determine audience and message via LLM
    severity = war_room.severity if war_room else "high"
    title = incident_details.get("title", "Incident")
    message = (
        f"War room active for {title}. "
        f"Severity: {severity}. "
        f"Actions: {len(actions)}. "
        f"Timeline entries: {len(timeline)}."
    )
    audience = "internal-stakeholders"

    try:
        result = await llm_structured(
            system_prompt=SYSTEM_COORDINATE_COMMS,
            user_prompt=(
                f"Incident: {title}\n"
                f"Severity: {severity}\n"
                f"Actions: {len(actions)}\n"
                f"Timeline entries: {len(timeline)}"
            ),
            output_schema=CommsOutput,
        )
        message = result.update_message
        audience = result.audience
    except Exception:
        logger.warning(
            "war_room_coordinator.llm_comms_fallback",
        )

    comm_log = await toolkit.send_comms(
        war_room=war_room,
        message=message,
        audience=audience,
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])

    return {
        "comms_log": [
            *state.get("comms_log", []),
            comm_log,
        ],
        "stage": WarRoomStage.COORDINATE_COMMS,
        "current_step": "coordinate_comms",
        "reasoning_chain": [
            *chain,
            (f"[coordinate_comms] Sent update to {audience} ({elapsed}ms)"),
        ],
    }


async def report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate the final war room summary report."""
    start = time.time()

    actions = state.get("action_items", [])
    timeline = state.get("timeline", [])
    comms = state.get("comms_log", [])
    role_assignments = state.get("role_assignments", [])

    stats: dict[str, Any] = {
        "roles_assigned": len(role_assignments),
        "actions_generated": len(actions),
        "timeline_entries": len(timeline),
        "comms_sent": len(comms),
    }

    # LLM enhancement for executive summary
    try:
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(
                f"Roles: {len(role_assignments)}\n"
                f"Actions: {len(actions)}\n"
                f"Timeline: {len(timeline)}\n"
                f"Communications: {len(comms)}"
            ),
            output_schema=ReportOutput,
        )
        stats["executive_summary"] = result.executive_summary
        stats["key_decisions"] = result.key_decisions
        stats["open_items"] = result.open_items
    except Exception:
        logger.warning(
            "war_room_coordinator.llm_report_fallback",
        )
        stats["executive_summary"] = "War room session completed."

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])

    total_ms = elapsed
    session_start = state.get("session_start", 0.0)
    if session_start:
        total_ms = int((time.time() - session_start) * 1000)

    return {
        "stats": stats,
        "stage": WarRoomStage.REPORT,
        "current_step": "report",
        "session_duration_ms": total_ms,
        "reasoning_chain": [
            *chain,
            (f"[report] Generated summary ({elapsed}ms)"),
        ],
    }
