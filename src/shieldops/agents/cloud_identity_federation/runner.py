"""Cloud Identity Federation Agent — Entry point and lifecycle."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import CloudIdentityFederationToolkit

logger = structlog.get_logger()


class CloudIdentityFederationRunner:
    """Runs the Cloud Identity Federation agent workflow."""

    def __init__(
        self,
        idp_clients: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudIdentityFederationToolkit(
            idp_clients=idp_clients,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("cloud_identity_federation_runner.init")

    async def analyze(
        self,
        tenant_id: str,
        identity_providers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full federation analysis."""
        if identity_providers is None:
            identity_providers = [
                "okta",
                "azure_ad",
                "google_workspace",
            ]

        request_id = str(uuid.uuid4())[:8]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "identity_providers": identity_providers,
            "reasoning_chain": [],
            "session_start": time.time(),
        }

        logger.info(
            "cloud_identity_federation_runner.analyze",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._repository.save(result)
            return result
        except Exception:
            logger.exception("cloud_identity_federation_runner.error")
            raise
