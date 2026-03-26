"""Security App Builder Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .models import DeploymentTarget
from .tools import SecurityAppBuilderToolkit

logger = structlog.get_logger()


class SecurityAppBuilderRunner:
    """Runs the Security App Builder agent workflow."""

    def __init__(
        self,
        code_store: Any | None = None,
        registry_client: Any | None = None,
        opa_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityAppBuilderToolkit(
            code_store=code_store,
            registry_client=registry_client,
            opa_client=opa_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("security_app_builder_runner.init")

    async def build(
        self,
        tenant_id: str = "",
        description: str = "",
        deployment_target: str = "dry_run",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Build a security app from NL description.

        Args:
            tenant_id: Tenant identifier.
            description: Natural language description
                of the desired security application.
            deployment_target: One of staging,
                production, or dry_run.
            request_id: Unique request identifier.

        Returns:
            Final state dict with generated code,
            validations, and deployment result.
        """
        target = DeploymentTarget(deployment_target)

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "nl_description": description,
            "deployment_target": target.value,
            "reasoning_chain": [],
        }

        logger.info(
            "security_app_builder_runner.build",
            tenant_id=tenant_id,
            request_id=request_id,
            target=target.value,
            description_len=len(description),
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("security_app_builder_runner.build.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist build results."""
        if self._repository:
            await self._repository.save_app_build(result)
