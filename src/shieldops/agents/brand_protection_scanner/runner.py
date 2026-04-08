"""Brand Protection Scanner Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.brand_protection_scanner.graph import (
    create_brand_protection_scanner_graph,
)
from shieldops.agents.brand_protection_scanner.models import BrandProtectionScannerState
from shieldops.agents.brand_protection_scanner.nodes import set_toolkit
from shieldops.agents.brand_protection_scanner.tools import BrandProtectionScannerToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class BrandProtectionScannerRunner:
    """Runner for brand_protection_scanner."""

    def __init__(self) -> None:
        self._toolkit = BrandProtectionScannerToolkit()
        set_toolkit(self._toolkit)
        graph = create_brand_protection_scanner_graph()
        self._app = graph.compile()
        self._results: dict[str, BrandProtectionScannerState] = {}

    @enforced("brand_protection_scanner")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> BrandProtectionScannerState:
        rid = f"bra-{uuid4().hex[:12]}"
        initial = BrandProtectionScannerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "brand_protection_scanner"}},
            )
            final = BrandProtectionScannerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = BrandProtectionScannerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> BrandProtectionScannerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
