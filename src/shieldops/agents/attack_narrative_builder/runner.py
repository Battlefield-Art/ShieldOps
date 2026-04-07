"""Attack Narrative Builder Agent runner — entry point
for building attack narratives from security events."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.attack_narrative_builder.graph import (
    create_attack_narrative_builder_graph,
)
from shieldops.agents.attack_narrative_builder.models import (
    AttackNarrativeBuilderState,
)
from shieldops.agents.attack_narrative_builder.nodes import set_toolkit
from shieldops.agents.attack_narrative_builder.tools import (
    AttackNarrativeBuilderToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class AttackNarrativeBuilderRunner:
    """Runner for the Attack Narrative Builder Agent.

    Usage:
        runner = AttackNarrativeBuilderRunner()
        result = await runner.run(
            sources=["siem", "edr"],
            time_range_hours=24,
            narrative_type="incident_summary",
        )
    """

    def __init__(
        self,
        event_source: Any | None = None,
        mitre_client: Any | None = None,
        correlation_engine: Any | None = None,
        narrative_store: Any | None = None,
        metrics_store: Any | None = None,
    ) -> None:
        self._toolkit = AttackNarrativeBuilderToolkit(
            siem_client=event_source,
            mitre_client=mitre_client,
            repository=narrative_store,
        )
        set_toolkit(self._toolkit)

        graph = create_attack_narrative_builder_graph()
        self._app = graph.compile()
        self._results: dict[str, AttackNarrativeBuilderState] = {}
        logger.info("anb_runner.initialized")

    @enforced("attack_narrative_builder")
    async def run(
        self,
        sources: list[str] | None = None,
        time_range_hours: int = 24,
        severity_filter: str = "low",
        narrative_type: str = "incident_summary",
        tenant_id: str = "",
    ) -> AttackNarrativeBuilderState:
        """Run the full narrative-building pipeline.

        Args:
            sources: Event sources to query (e.g., siem, edr, cloud_audit).
            time_range_hours: How far back to collect events.
            severity_filter: Minimum severity to include.
            narrative_type: Type of narrative to generate.
            tenant_id: Tenant identifier for multi-tenant deployments.

        Returns:
            Final AttackNarrativeBuilderState with the complete report.
        """
        request_id = f"anb-{uuid4().hex[:12]}"

        initial_state = AttackNarrativeBuilderState(
            request_id=request_id,
            tenant_id=tenant_id,
            config={
                "sources": sources or ["siem", "edr", "cloud_audit"],
                "time_range_hours": time_range_hours,
                "severity_filter": severity_filter,
                "narrative_type": narrative_type,
            },
        )

        logger.info(
            "anb_runner.starting",
            request_id=request_id,
            sources=sources,
            time_range_hours=time_range_hours,
            narrative_type=narrative_type,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "attack_narrative_builder",
                    },
                },
            )
            final = AttackNarrativeBuilderState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "anb_runner.completed",
                request_id=request_id,
                events=len(final.events),
                clusters=len(final.clusters),
                mappings=len(final.mitre_mappings),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "anb_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = AttackNarrativeBuilderState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> AttackNarrativeBuilderState | None:
        """Retrieve a cached narrative result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all narrative results as summaries."""
        return [
            {
                "request_id": rid,
                "events": len(s.events),
                "clusters": len(s.clusters),
                "mitre_mappings": len(s.mitre_mappings),
                "current_step": s.current_step,
                "duration_ms": s.session_duration_ms,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
