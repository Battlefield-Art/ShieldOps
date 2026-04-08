"""Credential Rotation Manager Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.credential_rotation_manager.graph import (
    create_credential_rotation_manager_graph,
)
from shieldops.agents.credential_rotation_manager.models import CredentialRotationManagerState
from shieldops.agents.credential_rotation_manager.nodes import set_toolkit
from shieldops.agents.credential_rotation_manager.tools import CredentialRotationManagerToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class CredentialRotationManagerRunner:
    """Runner for credential_rotation_manager."""

    def __init__(self) -> None:
        self._toolkit = CredentialRotationManagerToolkit()
        set_toolkit(self._toolkit)
        graph = create_credential_rotation_manager_graph()
        self._app = graph.compile()
        self._results: dict[str, CredentialRotationManagerState] = {}

    @enforced("credential_rotation_manager")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> CredentialRotationManagerState:
        rid = f"cre-{uuid4().hex[:12]}"
        initial = CredentialRotationManagerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "credential_rotation_manager"}},
            )
            final = CredentialRotationManagerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = CredentialRotationManagerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> CredentialRotationManagerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
