"""Zero Trust Validator Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.zero_trust_validator.graph import (
    create_zero_trust_validator_graph,
)
from shieldops.agents.zero_trust_validator.models import ZeroTrustValidatorState
from shieldops.agents.zero_trust_validator.nodes import set_toolkit
from shieldops.agents.zero_trust_validator.tools import ZeroTrustValidatorToolkit

logger = structlog.get_logger()


class ZeroTrustValidatorRunner:
    """Runner for zero_trust_validator."""

    def __init__(self) -> None:
        self._toolkit = ZeroTrustValidatorToolkit()
        set_toolkit(self._toolkit)
        graph = create_zero_trust_validator_graph()
        self._app = graph.compile()
        self._results: dict[str, ZeroTrustValidatorState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> ZeroTrustValidatorState:
        rid = f"zer-{uuid4().hex[:12]}"
        initial = ZeroTrustValidatorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "zero_trust_validator"}},
            )
            final = ZeroTrustValidatorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = ZeroTrustValidatorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> ZeroTrustValidatorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
