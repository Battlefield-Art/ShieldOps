"""Configuration Auditor Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.configuration_auditor.graph import (
    create_configuration_auditor_graph,
)
from shieldops.agents.configuration_auditor.models import (
    ConfigurationAuditorState,
)
from shieldops.agents.configuration_auditor.nodes import (
    set_toolkit,
)
from shieldops.agents.configuration_auditor.tools import (
    ConfigurationAuditorToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class ConfigurationAuditorRunner:
    """Runner for configuration_auditor."""

    def __init__(self) -> None:
        self._toolkit = ConfigurationAuditorToolkit()
        set_toolkit(self._toolkit)
        graph = create_configuration_auditor_graph()
        self._app = graph.compile()
        self._results: dict[str, ConfigurationAuditorState] = {}

    @enforced("configuration_auditor")
    async def execute(self, tenant_id: str = "default") -> ConfigurationAuditorState:
        rid = f"ca-{uuid4().hex[:12]}"
        initial = ConfigurationAuditorState(request_id=rid, tenant_id=tenant_id)
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": ("configuration_auditor")}},
            )
            final = ConfigurationAuditorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = ConfigurationAuditorState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> ConfigurationAuditorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
