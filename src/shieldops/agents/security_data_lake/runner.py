"""Security Data Lake Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_data_lake.graph import (
    create_security_data_lake_graph,
)
from shieldops.agents.security_data_lake.models import (
    DataQuery,
    SecurityDataLakeState,
)
from shieldops.agents.security_data_lake.nodes import (
    set_toolkit,
)
from shieldops.agents.security_data_lake.tools import (
    SecurityDataLakeToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class SecurityDataLakeRunner:
    """Runs unified data lake queries.

    Usage::

        runner = SecurityDataLakeRunner()
        result = await runner.query(
            tenant_id="acme",
            query_text="Show critical findings",
        )
    """

    def __init__(
        self,
        db_client: Any | None = None,
        metrics_client: Any | None = None,
        search_client: Any | None = None,
    ) -> None:
        self._toolkit = SecurityDataLakeToolkit(
            db_client=db_client,
            metrics_client=metrics_client,
            search_client=search_client,
        )
        set_toolkit(self._toolkit)

        graph = create_security_data_lake_graph()
        self._app = graph.compile()
        self._runs: dict[str, SecurityDataLakeState] = {}

    async def query(
        self,
        tenant_id: str,
        query_text: str,
        context: dict[str, Any] | None = None,
    ) -> SecurityDataLakeState:
        """Run a data lake query.

        Args:
            tenant_id: Tenant identifier.
            query_text: Natural language query.
            context: Optional overrides.

        Returns:
            Completed state with results.
        """
        request_id = f"lake-{uuid4().hex[:12]}"

        logger.info(
            "data_lake_started",
            request_id=request_id,
            tenant_id=tenant_id,
            query=query_text[:100],
        )

        initial = SecurityDataLakeState(
            request_id=request_id,
            tenant_id=tenant_id,
            query=DataQuery(raw_text=query_text),
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("data_lake.query") as span:
                span.set_attribute(
                    "data_lake.request_id",
                    request_id,
                )
                span.set_attribute(
                    "data_lake.tenant_id",
                    tenant_id,
                )

                final_dict = await self._app.ainvoke(
                    initial.model_dump(),
                    config={
                        "metadata": {
                            "request_id": request_id,
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final = SecurityDataLakeState.model_validate(final_dict)

                span.set_attribute(
                    "data_lake.records",
                    final.records_returned,
                )

            logger.info(
                "data_lake_completed",
                request_id=request_id,
                records=final.records_returned,
                sources=final.sources_queried,
                duration_ms=final.session_duration_ms,
            )

            self._runs[request_id] = final
            return final

        except Exception as e:
            logger.error(
                "data_lake_failed",
                request_id=request_id,
                error=str(e),
            )
            err = SecurityDataLakeState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._runs[request_id] = err
            return err

    def get_run(
        self,
        request_id: str,
    ) -> SecurityDataLakeState | None:
        """Retrieve a completed run."""
        return self._runs.get(request_id)

    def list_runs(self) -> list[dict[str, Any]]:
        """List all query runs."""
        return [
            {
                "request_id": rid,
                "tenant_id": s.tenant_id,
                "query": s.query.raw_text[:80],
                "status": s.current_step,
                "records": s.records_returned,
                "sources": s.sources_queried,
                "duration_ms": s.session_duration_ms,
                "error": s.error,
            }
            for rid, s in self._runs.items()
        ]
