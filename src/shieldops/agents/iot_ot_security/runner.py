"""IoT/OT Security Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import IoTOTSecurityToolkit

logger = structlog.get_logger()


class IoTOTSecurityRunner:
    """Runs the IoT/OT Security workflow."""

    def __init__(
        self,
        network_scanner: Any | None = None,
        ot_connector: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = IoTOTSecurityToolkit(
            network_scanner=network_scanner,
            ot_connector=ot_connector,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("iot_ot_security_runner.init")

    async def secure(
        self,
        tenant_id: str,
        network_zones: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute full IoT/OT security workflow.

        Args:
            tenant_id: Tenant identifier.
            network_zones: Zones to scan.
                Defaults to ["iot", "ot", "edge"].
            context: Optional additional context.

        Returns:
            dict with devices, anomalies, vulns,
            segmentation policies, and stats.
        """
        context = context or {}
        network_zones = network_zones or [
            "iot",
            "ot",
            "edge",
        ]
        request_id = context.get(
            "request_id",
            str(uuid.uuid4()),
        )

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "network_zones": network_zones,
            "reasoning_chain": [],
        }

        logger.info(
            "iot_ot_security_runner.secure",
            tenant_id=tenant_id,
            network_zones=network_zones,
            request_id=request_id,
        )
        try:
            start = time.time()
            result = await self._app.ainvoke(
                initial_state,
            )  # type: ignore[arg-type]
            if isinstance(result, dict):
                result["session_duration_ms"] = round(
                    (time.time() - start) * 1000,
                    2,
                )
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception(
                "iot_ot_security_runner.secure.error",
            )
            raise

    async def quick_discover(
        self,
        tenant_id: str,
        network_zones: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run discovery-only scan for device inventory.

        Lightweight entry point for asset inventory
        without full behavioral analysis or
        vulnerability assessment.
        """
        logger.info(
            "iot_ot_security_runner.quick_discover",
            tenant_id=tenant_id,
            zones=network_zones,
        )
        network_zones = network_zones or [
            "iot",
            "ot",
            "edge",
        ]
        devices = await self._toolkit.discover_devices(
            tenant_id=tenant_id,
            network_zones=network_zones,
        )
        unmanaged = [d for d in devices if not d.is_managed]
        ai_connected = [d for d in devices if d.is_ai_connected]
        return {
            "tenant_id": tenant_id,
            "total_devices": len(devices),
            "devices": [d.model_dump() for d in devices],
            "unmanaged_count": len(unmanaged),
            "ai_connected_count": len(ai_connected),
        }

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist IoT/OT security scan results."""
        if self._repository:
            await self._repository.save_iot_scan(
                result,
            )
