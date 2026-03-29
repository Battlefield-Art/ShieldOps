"""Runner for the Network Forensics Agent."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.network_forensics.graph import (
    create_network_forensics_graph,
)
from shieldops.agents.network_forensics.models import (
    NetworkForensicsState,
)
from shieldops.agents.network_forensics.nodes import (
    set_toolkit,
)
from shieldops.agents.network_forensics.tools import (
    NetworkForensicsToolkit,
)

logger = structlog.get_logger()


class NetworkForensicsRunner:
    """Runner for network forensics investigations."""

    def __init__(
        self,
        pcap_client: Any | None = None,
        threat_intel: Any | None = None,
    ) -> None:
        self._toolkit = NetworkForensicsToolkit(
            pcap_client=pcap_client,
            threat_intel=threat_intel,
        )
        set_toolkit(self._toolkit)
        graph = create_network_forensics_graph()
        self._app = graph.compile()
        self._results: dict[str, NetworkForensicsState] = {}
        logger.info("network_forensics_runner.initialized")

    async def investigate(
        self,
        tenant_id: str,
        captures: list[dict[str, Any]] | None = None,
    ) -> NetworkForensicsState:
        """Run a network forensics investigation."""
        request_id = f"nf-{uuid4().hex[:12]}"
        initial = NetworkForensicsState(
            request_id=request_id,
            tenant_id=tenant_id,
            captures=captures or [],
        )

        logger.info(
            "network_forensics_runner.starting",
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": request_id,
                        "agent": "network_forensics",
                    }
                },
            )
            final = NetworkForensicsState.model_validate(
                result,
            )
            self._results[request_id] = final
            logger.info(
                "network_forensics_runner.completed",
                request_id=request_id,
                duration_ms=final.session_duration_ms,
            )
            return final
        except Exception as e:
            logger.error(
                "network_forensics_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            err_state = NetworkForensicsState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = err_state
            return err_state

    def get_result(
        self,
        request_id: str,
    ) -> NetworkForensicsState | None:
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        return [
            {
                "request_id": rid,
                "current_step": s.current_step,
                "sessions": s.sessions_reconstructed,
                "exfil_paths": len(s.exfil_paths),
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
