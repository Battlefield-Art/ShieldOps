"""Cloud Resource Tagger Agent runner — entry point
for automated cloud resource tagging."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cloud_resource_tagger.graph import (
    create_cloud_resource_tagger_graph,
)
from shieldops.agents.cloud_resource_tagger.models import (
    CloudResourceTaggerState,
)
from shieldops.agents.cloud_resource_tagger.nodes import (
    set_toolkit,
)
from shieldops.agents.cloud_resource_tagger.tools import (
    CloudResourceTaggerToolkit,
)

logger = structlog.get_logger()


class CloudResourceTaggerRunner:
    """Runner for the Cloud Resource Tagger Agent."""

    def __init__(
        self,
        aws_client: Any | None = None,
        gcp_client: Any | None = None,
        azure_client: Any | None = None,
        tag_policy_store: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudResourceTaggerToolkit(
            aws_client=aws_client,
            gcp_client=gcp_client,
            azure_client=azure_client,
            tag_policy_store=tag_policy_store,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cloud_resource_tagger_graph()
        self._app = graph.compile()
        self._results: dict[str, CloudResourceTaggerState] = {}
        logger.info("crt_runner.initialized")

    async def tag_resources(
        self,
        tenant_id: str = "",
        providers: list[str] | None = None,
    ) -> CloudResourceTaggerState:
        """Run cloud resource tagging cycle."""
        request_id = f"crt-{uuid4().hex[:12]}"

        initial_state = CloudResourceTaggerState(
            request_id=request_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "crt_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
            providers=providers,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "cloud_resource_tagger",
                    },
                },
            )
            final = CloudResourceTaggerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "crt_runner.completed",
                request_id=request_id,
                total=final.total_resources,
                untagged=final.untagged_count,
                compliance=final.compliance_pct,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "crt_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = CloudResourceTaggerState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> CloudResourceTaggerState | None:
        """Retrieve a cached tagging result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all tagging results as summaries."""
        return [
            {
                "request_id": rid,
                "total": s.total_resources,
                "untagged": s.untagged_count,
                "compliance": s.compliance_pct,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
