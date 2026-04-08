"""War Room Coordinator Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.war_room_coordinator.graph import (
    create_war_room_coordinator_graph,
)
from shieldops.agents.war_room_coordinator.models import (
    WarRoomCoordinatorState,
)
from shieldops.agents.war_room_coordinator.nodes import (
    set_toolkit,
)
from shieldops.agents.war_room_coordinator.tools import (
    WarRoomCoordinatorToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class WarRoomCoordinatorRunner:
    """Runner for the War Room Coordinator Agent."""

    def __init__(
        self,
        roster_service: Any | None = None,
        comms_service: Any | None = None,
    ) -> None:
        self._toolkit = WarRoomCoordinatorToolkit(
            roster_service=roster_service,
            comms_service=comms_service,
        )
        set_toolkit(self._toolkit)
        graph = create_war_room_coordinator_graph()
        self._app = graph.compile()
        self._results: dict[str, WarRoomCoordinatorState] = {}
        logger.info(
            "war_room_coordinator_runner.initialized",
        )

    @enforced("war_room_coordinator")
    async def execute(
        self,
        tenant_id: str,
        incident_id: str,
        incident_details: dict[str, Any] | None = None,
    ) -> WarRoomCoordinatorState:
        """Run the war room coordination workflow."""
        session_id = f"wrc-{uuid4().hex[:12]}"
        initial = WarRoomCoordinatorState(
            request_id=session_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            incident_details=incident_details or {},
        )

        logger.info(
            "war_room_coordinator.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "war_room_coordinator",
                    }
                },
            )
            final = WarRoomCoordinatorState.model_validate(result)
            self._results[session_id] = final

            logger.info(
                "war_room_coordinator.completed",
                session_id=session_id,
                war_room_id=final.war_room.id,
                roles=len(final.role_assignments),
                actions=len(final.action_items),
                timeline=len(final.timeline),
                comms=len(final.comms_log),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "war_room_coordinator.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = WarRoomCoordinatorState(
                request_id=session_id,
                tenant_id=tenant_id,
                incident_id=incident_id,
                error=str(e),
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> WarRoomCoordinatorState | None:
        """Retrieve a stored result by session ID."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all war room coordination summaries."""
        return [
            {
                "session_id": sid,
                "tenant_id": s.tenant_id,
                "incident_id": s.incident_id,
                "war_room_id": s.war_room.id,
                "roles": len(s.role_assignments),
                "actions": len(s.action_items),
                "timeline": len(s.timeline),
                "comms": len(s.comms_log),
                "stage": s.stage,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
