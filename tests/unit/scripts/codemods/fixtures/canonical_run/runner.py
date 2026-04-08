"""Canonical async-def-run runner fixture."""

from __future__ import annotations

from tests.unit.scripts.codemods.fixtures.canonical_run.models import CanonicalRunState
from tests.unit.scripts.codemods.fixtures.canonical_run.nodes import set_toolkit
from tests.unit.scripts.codemods.fixtures.canonical_run.tools import CanonicalRunToolkit


class CanonicalRunRunner:
    def __init__(self) -> None:
        self._toolkit = CanonicalRunToolkit()
        set_toolkit(self._toolkit)

    async def run(self, tenant_id: str = "default") -> CanonicalRunState:
        return CanonicalRunState()
