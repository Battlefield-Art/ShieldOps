"""Custom Agent Factory runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.custom_agent_factory.graph import (
    create_custom_agent_factory_graph,
)
from shieldops.agents.custom_agent_factory.models import (
    AgentRequirement,
    CustomAgentFactoryState,
)
from shieldops.agents.custom_agent_factory.nodes import (
    set_toolkit,
)
from shieldops.agents.custom_agent_factory.tools import (
    CustomAgentFactoryToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class CustomAgentFactoryRunner:
    """Creates custom agents from NL descriptions.

    Usage::

        runner = CustomAgentFactoryRunner()
        result = await runner.create(
            tenant_id="acme",
            description="Monitor S3 bucket access",
        )
    """

    def __init__(
        self,
        registry_client: Any | None = None,
        template_store: Any | None = None,
        validator_client: Any | None = None,
    ) -> None:
        self._toolkit = CustomAgentFactoryToolkit(
            registry_client=registry_client,
            template_store=template_store,
            validator_client=validator_client,
        )
        set_toolkit(self._toolkit)

        graph = create_custom_agent_factory_graph()
        self._app = graph.compile()
        self._runs: dict[str, CustomAgentFactoryState] = {}

    async def create(
        self,
        tenant_id: str,
        description: str,
        context: dict[str, Any] | None = None,
    ) -> CustomAgentFactoryState:
        """Create a custom agent from description.

        Args:
            tenant_id: Tenant identifier.
            description: NL description of agent.
            context: Optional overrides.

        Returns:
            Completed state with generated agent.
        """
        request_id = f"factory-{uuid4().hex[:12]}"

        logger.info(
            "agent_factory_started",
            request_id=request_id,
            tenant_id=tenant_id,
            description=description[:100],
        )

        initial = CustomAgentFactoryState(
            request_id=request_id,
            tenant_id=tenant_id,
            requirements=AgentRequirement(
                description=description,
            ),
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("agent_factory.create") as span:
                span.set_attribute(
                    "agent_factory.request_id",
                    request_id,
                )
                span.set_attribute(
                    "agent_factory.tenant_id",
                    tenant_id,
                )

                final_dict = await self._app.ainvoke(
                    initial.model_dump(),
                    config={
                        "metadata": {
                            "request_id": request_id,
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final = CustomAgentFactoryState.model_validate(final_dict)

                span.set_attribute(
                    "agent_factory.quality",
                    final.code_quality_score,
                )

            logger.info(
                "agent_factory_completed",
                request_id=request_id,
                agent=final.requirements.agent_name,
                quality=final.code_quality_score,
                registered=(final.registration.registered),
                duration_ms=final.session_duration_ms,
            )

            self._runs[request_id] = final
            return final

        except Exception as e:
            logger.error(
                "agent_factory_failed",
                request_id=request_id,
                error=str(e),
            )
            err = CustomAgentFactoryState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._runs[request_id] = err
            return err

    def get_run(
        self,
        request_id: str,
    ) -> CustomAgentFactoryState | None:
        """Retrieve a completed run."""
        return self._runs.get(request_id)

    def list_runs(self) -> list[dict[str, Any]]:
        """List all factory runs."""
        return [
            {
                "request_id": rid,
                "tenant_id": s.tenant_id,
                "agent": (s.requirements.agent_name),
                "status": s.current_step,
                "quality": s.code_quality_score,
                "registered": (s.registration.registered),
                "duration_ms": (s.session_duration_ms),
                "error": s.error,
            }
            for rid, s in self._runs.items()
        ]
