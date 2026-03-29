"""Endpoint Forensics Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import EndpointForensicsToolkit

logger = structlog.get_logger()


class EndpointForensicsRunner:
    """Runs the Endpoint Forensics agent workflow."""

    def __init__(
        self,
        edr_client: Any | None = None,
        forensics_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = EndpointForensicsToolkit(
            edr_client=edr_client,
            forensics_client=forensics_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("endpoint_forensics_runner.init")

    async def run(
        self,
        tenant_id: str,
        endpoint_id: str = "",
        case_id: str = "",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the forensics investigation workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "endpoint_id": endpoint_id,
            "case_id": case_id,
            "reasoning_chain": [],
        }
        logger.info(
            "endpoint_forensics_runner.run",
            request_id=request_id,
            endpoint_id=endpoint_id,
            case_id=case_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._repository.save(result)
            return result
        except Exception:
            logger.exception("endpoint_forensics_runner.error")
            raise
