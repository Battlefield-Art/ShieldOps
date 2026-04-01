"""Threat Actor Profiler runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_actor_profiler.graph import (
    create_threat_actor_profiler_graph,
)
from shieldops.agents.threat_actor_profiler.models import (
    ThreatActorProfilerState,
)
from shieldops.agents.threat_actor_profiler.nodes import (
    set_toolkit,
)
from shieldops.agents.threat_actor_profiler.tools import (
    ThreatActorProfilerToolkit,
)

logger = structlog.get_logger()


class ThreatActorProfilerRunner:
    """Runner for the Threat Actor Profiler Agent."""

    def __init__(
        self,
        intel_client: Any | None = None,
        mitre_client: Any | None = None,
        telemetry_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ThreatActorProfilerToolkit(
            intel_client=intel_client,
            mitre_client=mitre_client,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_threat_actor_profiler_graph()
        self._app = graph.compile()
        self._results: dict[str, ThreatActorProfilerState] = {}
        logger.info("tap_runner.initialized")

    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> ThreatActorProfilerState:
        """Run threat actor profiling workflow."""
        sid = f"tap-{uuid4().hex[:12]}"
        initial = ThreatActorProfilerState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "tap_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "threat_actor_profiler",
                    },
                },
            )
            final = ThreatActorProfilerState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "tap_runner.completed",
                session_id=sid,
                profiles=len(final.profiles),
                ttp_mappings=len(final.ttp_mappings),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "tap_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = ThreatActorProfilerState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> ThreatActorProfilerState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "profiles": len(s.profiles),
                "ttp_mappings": len(s.ttp_mappings),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
