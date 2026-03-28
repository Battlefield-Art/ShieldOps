"""APT Emulator Agent runner — entry point."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.apt_emulator.graph import (
    create_apt_emulator_graph,
)
from shieldops.agents.apt_emulator.models import (
    APTEmulatorState,
    CampaignDesign,
)
from shieldops.agents.apt_emulator.nodes import (
    set_toolkit,
)
from shieldops.agents.apt_emulator.tools import (
    APTEmulatorToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class APTEmulatorRunner:
    """Runs safe APT emulation campaigns.

    Usage::

        runner = APTEmulatorRunner()
        result = await runner.emulate(
            tenant_id="acme",
            apt_group="APT29",
        )
    """

    def __init__(
        self,
        attack_client: Any | None = None,
        defense_monitor: Any | None = None,
        telemetry_client: Any | None = None,
    ) -> None:
        self._toolkit = APTEmulatorToolkit(
            attack_client=attack_client,
            defense_monitor=defense_monitor,
            telemetry_client=telemetry_client,
        )
        set_toolkit(self._toolkit)

        graph = create_apt_emulator_graph()
        self._app = graph.compile()
        self._runs: dict[str, APTEmulatorState] = {}

    async def emulate(
        self,
        tenant_id: str,
        apt_group: str = "APT29",
        target_env: str = "production",
        context: dict[str, Any] | None = None,
    ) -> APTEmulatorState:
        """Run a full APT emulation campaign.

        Args:
            tenant_id: Tenant to emulate against.
            apt_group: APT group to emulate.
            target_env: Target environment name.
            context: Optional overrides.

        Returns:
            Completed APTEmulatorState.
        """
        request_id = f"apt-{uuid4().hex[:12]}"

        logger.info(
            "apt_emulation_started",
            request_id=request_id,
            tenant_id=tenant_id,
            apt_group=apt_group,
        )

        initial_state = APTEmulatorState(
            request_id=request_id,
            tenant_id=tenant_id,
            campaign=CampaignDesign(
                apt_group=apt_group,
                target_environment=target_env,
            ),
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("apt_emulator.emulate") as span:
                span.set_attribute(
                    "apt_emulator.request_id",
                    request_id,
                )
                span.set_attribute(
                    "apt_emulator.tenant_id",
                    tenant_id,
                )
                span.set_attribute(
                    "apt_emulator.apt_group",
                    apt_group,
                )

                final_dict = await self._app.ainvoke(
                    initial_state.model_dump(),
                    config={
                        "metadata": {
                            "request_id": request_id,
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final = APTEmulatorState.model_validate(final_dict)

                span.set_attribute(
                    "apt_emulator.score",
                    final.overall_score,
                )

            logger.info(
                "apt_emulation_completed",
                request_id=request_id,
                score=final.overall_score,
                blocked=final.phases_blocked,
                evaded=final.phases_evaded,
                duration_ms=final.session_duration_ms,
            )

            self._runs[request_id] = final
            return final

        except Exception as e:
            logger.error(
                "apt_emulation_failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = APTEmulatorState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._runs[request_id] = error_state
            return error_state

    def get_run(
        self,
        request_id: str,
    ) -> APTEmulatorState | None:
        """Retrieve a completed run by ID."""
        return self._runs.get(request_id)

    def list_runs(self) -> list[dict[str, Any]]:
        """List all emulation runs."""
        return [
            {
                "request_id": rid,
                "tenant_id": s.tenant_id,
                "apt_group": s.campaign.apt_group,
                "status": s.current_step,
                "score": s.overall_score,
                "blocked": s.phases_blocked,
                "evaded": s.phases_evaded,
                "duration_ms": s.session_duration_ms,
                "error": s.error,
            }
            for rid, s in self._runs.items()
        ]
