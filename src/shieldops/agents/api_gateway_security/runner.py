"""API Gateway Security Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.api_gateway_security.graph import (
    create_api_gateway_security_graph,
)
from shieldops.agents.api_gateway_security.models import (
    APIGatewaySecurityState,
)
from shieldops.agents.api_gateway_security.nodes import (
    set_toolkit,
)
from shieldops.agents.api_gateway_security.tools import (
    APIGatewaySecurityToolkit,
)

logger = structlog.get_logger()


class APIGatewaySecurityRunner:
    """Runner for api_gateway_security."""

    def __init__(self) -> None:
        self._toolkit = APIGatewaySecurityToolkit()
        set_toolkit(self._toolkit)
        graph = create_api_gateway_security_graph()
        self._app = graph.compile()
        self._results: dict[str, APIGatewaySecurityState] = {}

    async def execute(self, tenant_id: str = "default") -> APIGatewaySecurityState:
        rid = f"ags-{uuid4().hex[:12]}"
        initial = APIGatewaySecurityState(request_id=rid, tenant_id=tenant_id)
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "api_gateway_security"}},
            )
            final = APIGatewaySecurityState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = APIGatewaySecurityState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> APIGatewaySecurityState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
