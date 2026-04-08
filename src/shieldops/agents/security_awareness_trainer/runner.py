"""Security Awareness Trainer Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_awareness_trainer.graph import (
    create_security_awareness_trainer_graph,
)
from shieldops.agents.security_awareness_trainer.nodes import (
    set_toolkit,
)
from shieldops.agents.security_awareness_trainer.tools import (
    SecurityAwarenessTrainerToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class SecurityAwarenessTrainerRunner:
    """Runs security awareness training workflows."""

    def __init__(
        self,
        client: Any = None,
    ) -> None:
        self._toolkit = SecurityAwarenessTrainerToolkit(
            client=client,
        )
        set_toolkit(self._toolkit)
        graph = create_security_awareness_trainer_graph()
        self._app = graph.compile()
        self._results: dict[str, Any] = {}

    @enforced("security_awareness_trainer")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> dict[str, Any]:
        """Run a full awareness training workflow."""
        rid = f"sat-{uuid4().hex[:8]}"
        logger.info(
            "sat_run_started",
            request_id=rid,
            tenant_id=tenant_id,
        )
        result = await self._app.ainvoke(
            {
                "request_id": rid,
                "tenant_id": tenant_id,
            },
        )
        self._results[rid] = result
        return result

    def get_result(
        self,
        request_id: str,
    ) -> dict[str, Any] | None:
        """Retrieve a result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[str]:
        """List all stored request IDs."""
        return list(self._results.keys())
