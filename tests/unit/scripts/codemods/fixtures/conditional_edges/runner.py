"""Runner with conditional edges."""

from __future__ import annotations

from tests.unit.scripts.codemods.fixtures.conditional_edges.models import ConditionalEdgesState
from tests.unit.scripts.codemods.fixtures.conditional_edges.nodes import set_toolkit
from tests.unit.scripts.codemods.fixtures.conditional_edges.tools import ConditionalEdgesToolkit


class ConditionalEdgesRunner:
    def __init__(self) -> None:
        self._toolkit = ConditionalEdgesToolkit()
        set_toolkit(self._toolkit)

    async def run(self) -> ConditionalEdgesState:
        return ConditionalEdgesState()
