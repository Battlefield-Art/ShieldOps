"""Consent Manager Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.consent_manager.graph import (
    create_consent_manager_graph,
)
from shieldops.agents.consent_manager.models import ConsentManagerState
from shieldops.agents.consent_manager.nodes import set_toolkit
from shieldops.agents.consent_manager.tools import ConsentManagerToolkit

logger = structlog.get_logger()


class ConsentManagerRunner:
    """Runner for consent_manager."""

    def __init__(self) -> None:
        self._toolkit = ConsentManagerToolkit()
        set_toolkit(self._toolkit)
        graph = create_consent_manager_graph()
        self._app = graph.compile()
        self._results: dict[str, ConsentManagerState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> ConsentManagerState:
        rid = f"con-{uuid4().hex[:12]}"
        initial = ConsentManagerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "consent_manager"}},
            )
            final = ConsentManagerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = ConsentManagerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> ConsentManagerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
