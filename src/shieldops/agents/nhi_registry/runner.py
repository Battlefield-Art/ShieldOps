"""NHI Registry Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import NHIRegistryToolkit

logger = structlog.get_logger()


class NHIRegistryRunner:
    """Runs the NHI Registry agent workflow."""

    def __init__(
        self,
        aws_client: Any | None = None,
        gcp_client: Any | None = None,
        azure_client: Any | None = None,
        k8s_client: Any | None = None,
        github_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = NHIRegistryToolkit(
            aws_client=aws_client,
            gcp_client=gcp_client,
            azure_client=azure_client,
            k8s_client=k8s_client,
            github_client=github_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("nhi_registry_runner.init")

    async def scan(
        self,
        targets: list[str] | None = None,
        context: dict[str, Any] | None = None,
        request_id: str = "",
        include_shadow_ai: bool = True,
    ) -> dict[str, Any]:
        """Execute the full NHI discovery and assessment workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "scan_targets": targets or [],
            "include_shadow_ai": include_shadow_ai,
            "reasoning_chain": [],
        }

        logger.info(
            "nhi_registry_runner.scan",
            request_id=request_id,
            targets=targets,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("nhi_registry_runner.scan.error")
            raise

    async def get_registry(
        self,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve the current NHI registry with optional filters."""
        logger.info("nhi_registry_runner.get_registry", filters=filters)

        if self._repository:
            try:
                return await self._repository.get_identities(filters=filters)
            except Exception:
                logger.exception("nhi_registry_runner.get_registry.error")

        # Run a scan to populate registry if no repository
        result = await self.scan(
            targets=filters.get("targets", []) if filters else [],
        )
        identities = result.get("discovered_identities", [])

        if filters:
            nhi_type = filters.get("nhi_type")
            if nhi_type:
                identities = [i for i in identities if i.get("nhi_type") == nhi_type]
            provider = filters.get("provider")
            if provider:
                identities = [i for i in identities if i.get("provider") == provider]
            status = filters.get("status")
            if status:
                identities = [i for i in identities if i.get("status") == status]

        return identities

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist NHI scan results."""
        if self._repository:
            await self._repository.save_nhi_scan(result)
