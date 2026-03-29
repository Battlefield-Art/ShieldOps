"""Tokenization Manager Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.tokenization_manager.graph import (
    create_tokenization_manager_graph,
)
from shieldops.agents.tokenization_manager.models import TokenizationManagerState
from shieldops.agents.tokenization_manager.nodes import set_toolkit
from shieldops.agents.tokenization_manager.tools import TokenizationManagerToolkit

logger = structlog.get_logger()


class TokenizationManagerRunner:
    """Runner for tokenization_manager."""

    def __init__(self) -> None:
        self._toolkit = TokenizationManagerToolkit()
        set_toolkit(self._toolkit)
        graph = create_tokenization_manager_graph()
        self._app = graph.compile()
        self._results: dict[str, TokenizationManagerState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> TokenizationManagerState:
        rid = f"tok-{uuid4().hex[:12]}"
        initial = TokenizationManagerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "tokenization_manager"}},
            )
            final = TokenizationManagerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = TokenizationManagerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> TokenizationManagerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
