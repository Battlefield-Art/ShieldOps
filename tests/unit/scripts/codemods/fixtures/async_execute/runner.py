"""Runner fixture using async def execute."""

from __future__ import annotations

from tests.unit.scripts.codemods.fixtures.async_execute.models import AsyncExecuteState
from tests.unit.scripts.codemods.fixtures.async_execute.nodes import set_toolkit
from tests.unit.scripts.codemods.fixtures.async_execute.tools import AsyncExecuteToolkit


class AsyncExecuteRunner:
    def __init__(self) -> None:
        self._toolkit = AsyncExecuteToolkit()
        set_toolkit(self._toolkit)

    async def execute(self, tenant_id: str = "default") -> AsyncExecuteState:
        return AsyncExecuteState()
