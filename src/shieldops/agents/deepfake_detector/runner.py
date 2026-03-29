"""Deepfake Detector Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import DeepfakeDetectorToolkit

logger = structlog.get_logger()


class DeepfakeDetectorRunner:
    """Runs the Deepfake Detector agent workflow."""

    def __init__(
        self,
        c2pa_client: Any | None = None,
        forensics_client: Any | None = None,
        model_detector_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DeepfakeDetectorToolkit(
            c2pa_client=c2pa_client,
            forensics_client=forensics_client,
            model_detector_client=model_detector_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("deepfake_detector_runner.init")

    async def detect(
        self,
        tenant_id: str,
        submissions: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Execute the full deepfake detection workflow.

        Args:
            tenant_id: Tenant identifier.
            submissions: List of media submission dicts with keys:
                file_name, mime_type, media_type, content,
                source_url, submitted_by, metadata.

        Returns:
            Final state dict with classifications,
            evidence packages, and statistics.
        """
        submissions = submissions or []
        request_id = f"dfd-{uuid.uuid4().hex[:10]}"

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "submissions": submissions,
            "reasoning_chain": [],
        }

        logger.info(
            "deepfake_detector_runner.detect",
            request_id=request_id,
            tenant_id=tenant_id,
            submission_count=len(submissions),
        )
        start = time.time()
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            result["session_duration_ms"] = (time.time() - start) * 1000
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception(
                "deepfake_detector_runner.detect.error",
                request_id=request_id,
            )
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist detection results."""
        if self._repository:
            await self._repository.save_analysis_run(result)
