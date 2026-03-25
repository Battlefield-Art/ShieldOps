"""Container Security Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import ContainerSecurityToolkit

logger = structlog.get_logger()


class ContainerSecurityRunner:
    """Runs the Container Security workflow."""

    def __init__(
        self,
        registry_client: Any | None = None,
        k8s_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ContainerSecurityToolkit(
            registry_client=registry_client,
            k8s_client=k8s_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("container_security_runner.init")

    async def scan(
        self,
        tenant_id: str,
        namespaces: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full container security scan workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            namespaces: Kubernetes namespaces to scan. Defaults to ["default"].
            context: Optional additional context for the scan.

        Returns:
            dict with vulnerabilities, anomalies, admission decisions,
            remediations, and stats.
        """
        context = context or {}
        namespaces = namespaces or ["default"]
        request_id = context.get("request_id", str(uuid.uuid4()))

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "namespaces": namespaces,
            "reasoning_chain": [],
        }

        logger.info(
            "container_security_runner.scan",
            tenant_id=tenant_id,
            namespaces=namespaces,
            request_id=request_id,
        )
        try:
            start = time.time()
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if isinstance(result, dict):
                result["session_duration_ms"] = round((time.time() - start) * 1000, 2)
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("container_security_runner.scan.error")
            raise

    async def quick_scan(
        self,
        tenant_id: str,
        images: list[str],
    ) -> dict[str, Any]:
        """Run a quick admission-only scan on a list of images.

        This is the lightweight entry point for CI/CD pipeline integration
        — evaluates images against admission policies without full runtime
        analysis.
        """
        logger.info(
            "container_security_runner.quick_scan",
            tenant_id=tenant_id,
            image_count=len(images),
        )
        decisions = await self._toolkit.enforce_admission(images=images)
        denied = [d for d in decisions if d.decision == "deny"]
        return {
            "tenant_id": tenant_id,
            "total_images": len(images),
            "decisions": [d.model_dump() for d in decisions],
            "denied_count": len(denied),
            "pass": len(denied) == 0,
        }

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist container security scan results."""
        if self._repository:
            await self._repository.save_container_scan(result)
