"""Node implementations for the War Room Automator."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.utils.llm import llm_structured

from .models import WRAStage
from .prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_REPORT,
    AnalyzeOutput,
    ReportOutput,
)
from .tools import WarRoomAutomatorToolkit

logger = structlog.get_logger()

_toolkit: WarRoomAutomatorToolkit | None = None


def set_toolkit(
    toolkit: WarRoomAutomatorToolkit,
) -> None:
    """Set the shared toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> WarRoomAutomatorToolkit:
    if _toolkit is None:
        return WarRoomAutomatorToolkit()
    return _toolkit


async def detect_incident(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Detect and classify incident for war room."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.detect_incident(
        incident_id=state.get("incident_id", ""),
        incident_title=state.get("incident_title", ""),
        incident_severity=state.get(
            "incident_severity",
            "",
        ),
        affected_services=state.get(
            "affected_services",
            [],
        ),
    )

    try:
        ctx = _json.dumps(
            {
                "title": state.get("incident_title", ""),
                "severity": state.get(
                    "incident_severity",
                    "",
                ),
                "services": state.get(
                    "affected_services",
                    [],
                ),
            },
            default=str,
        )
        llm = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=f"Analyze incident:\n{ctx}",
            schema=AnalyzeOutput,
        )
        if hasattr(llm, "room_type") and llm.room_type:
            result["llm_room_type"] = llm.room_type
    except Exception:
        logger.debug("wra.llm_skipped", node="detect")

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "detect_incident",
        "stage": WRAStage.CREATE_ROOM.value,
        "detection_result": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "detect_incident",
                "detail": (f"Type={result.get('room_type')}"),
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "detect_ms": elapsed,
        },
    }


async def create_room(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Create the war room."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.create_room(
        detection_result=state.get(
            "detection_result",
            {},
        ),
        incident_title=state.get("incident_title", ""),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "create_room",
        "stage": WRAStage.ASSEMBLE_TEAM.value,
        "room_config": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "create_room",
                "detail": (f"Room={result.get('room_id')}"),
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "create_room_ms": elapsed,
        },
    }


async def assemble_team(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Assemble the war room team."""
    start = time.time()
    tk = _get_toolkit()

    roster = await tk.assemble_team(
        room_config=state.get("room_config", {}),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "assemble_team",
        "stage": WRAStage.SHARE_CONTEXT.value,
        "team_roster": roster,
        "reasoning_chain": [
            *chain,
            {
                "step": "assemble_team",
                "detail": f"Team size={len(roster)}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "assemble_ms": elapsed,
        },
    }


async def share_context(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Share incident context in war room."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.share_context(
        room_config=state.get("room_config", {}),
        incident_description=state.get(
            "incident_description",
            "",
        ),
        affected_services=state.get(
            "affected_services",
            [],
        ),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "share_context",
        "stage": WRAStage.COORDINATE_ACTIONS.value,
        "shared_context": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "share_context",
                "detail": "Context shared in war room",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "share_ms": elapsed,
        },
    }


async def coordinate_actions(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Coordinate action items."""
    start = time.time()
    tk = _get_toolkit()

    actions = await tk.coordinate_actions(
        team_roster=state.get("team_roster", []),
        shared_context=state.get("shared_context", {}),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "coordinate_actions",
        "stage": WRAStage.REPORT.value,
        "action_items": actions,
        "reasoning_chain": [
            *chain,
            {
                "step": "coordinate_actions",
                "detail": f"Actions={len(actions)}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "coordinate_ms": elapsed,
        },
    }


async def report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate war room summary report."""
    start = time.time()
    report_data: dict[str, Any] = {
        "room_config": state.get("room_config", {}),
        "team_size": len(state.get("team_roster", [])),
        "actions": len(state.get("action_items", [])),
    }

    try:
        ctx = _json.dumps(report_data, default=str)
        llm = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate report:\n{ctx}",
            schema=ReportOutput,
        )
        if hasattr(llm, "executive_summary"):
            report_data["executive_summary"] = llm.executive_summary
            report_data["outcomes"] = llm.outcomes
    except Exception:
        logger.debug("wra.llm_skipped", node="report")

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "report",
        "stage": WRAStage.REPORT.value,
        "stats": {
            **state.get("stats", {}),
            **report_data,
            "report_ms": elapsed,
        },
        "reasoning_chain": [
            *chain,
            {
                "step": "report",
                "detail": "War room report generated",
                "elapsed_ms": elapsed,
            },
        ],
    }
