"""Open Source License Scanner Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.open_source_license_scanner.graph import (
    create_open_source_license_scanner_graph,
)
from shieldops.agents.open_source_license_scanner.models import OpenSourceLicenseScannerState
from shieldops.agents.open_source_license_scanner.nodes import set_toolkit
from shieldops.agents.open_source_license_scanner.tools import OpenSourceLicenseScannerToolkit

logger = structlog.get_logger()


class OpenSourceLicenseScannerRunner:
    """Runner for open_source_license_scanner."""

    def __init__(self) -> None:
        self._toolkit = OpenSourceLicenseScannerToolkit()
        set_toolkit(self._toolkit)
        graph = create_open_source_license_scanner_graph()
        self._app = graph.compile()
        self._results: dict[str, OpenSourceLicenseScannerState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> OpenSourceLicenseScannerState:
        rid = f"ope-{uuid4().hex[:12]}"
        initial = OpenSourceLicenseScannerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "open_source_license_scanner"}},
            )
            final = OpenSourceLicenseScannerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = OpenSourceLicenseScannerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> OpenSourceLicenseScannerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
