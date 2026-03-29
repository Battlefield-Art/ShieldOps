"""Federated Learning Security Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.federated_learning_security.graph import (
    create_federated_learning_security_graph,
)
from shieldops.agents.federated_learning_security.models import FederatedLearningSecurityState
from shieldops.agents.federated_learning_security.nodes import set_toolkit
from shieldops.agents.federated_learning_security.tools import FederatedLearningSecurityToolkit

logger = structlog.get_logger()


class FederatedLearningSecurityRunner:
    """Runner for federated_learning_security."""

    def __init__(self) -> None:
        self._toolkit = FederatedLearningSecurityToolkit()
        set_toolkit(self._toolkit)
        graph = create_federated_learning_security_graph()
        self._app = graph.compile()
        self._results: dict[str, FederatedLearningSecurityState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> FederatedLearningSecurityState:
        rid = f"fed-{uuid4().hex[:12]}"
        initial = FederatedLearningSecurityState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "federated_learning_security"}},
            )
            final = FederatedLearningSecurityState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = FederatedLearningSecurityState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> FederatedLearningSecurityState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
