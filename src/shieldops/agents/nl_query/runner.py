"""Entry point for the Natural Language Query agent."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.nl_query.graph import build_graph
from shieldops.agents.nl_query.models import (
    NLQueryRequest,
    NLQueryResponse,
    NLQueryState,
    OutputFormat,
    QueryType,
)
from shieldops.agents.nl_query.tools import NLQueryToolkit

logger = structlog.get_logger()


class NLQueryRunner:
    """Runner for the NL Query agent — builds graph, runs queries."""

    agent_name = "nl_query"

    def __init__(self, storage: Any = None) -> None:
        self._toolkit = NLQueryToolkit(storage=storage)
        self._graph = build_graph(self._toolkit).compile()
        self._history: dict[str, NLQueryResponse] = {}
        logger.info("nl_query_runner.initialized")

    async def run(
        self,
        request: NLQueryRequest,
        *,
        org_id: str,
    ) -> NLQueryResponse:
        """Execute the full NL→SQL→results pipeline."""
        session_id = f"nl-{uuid4().hex[:12]}"
        start = time.monotonic()

        initial = NLQueryState(
            request_id=session_id,
            org_id=org_id,
            question=request.question,
            time_range=request.time_range or "",
            max_rows=request.max_rows,
        )

        try:
            result_dict = await self._graph.ainvoke(initial.model_dump())
            final = NLQueryState.model_validate(result_dict)
        except Exception as exc:
            logger.error("nl_query_runner.failed", session_id=session_id, error=str(exc))
            response = NLQueryResponse(
                question=request.question,
                error=str(exc),
                format=OutputFormat.ERROR,
                markdown=f"**Error:** {exc}",
                duration_ms=int((time.monotonic() - start) * 1000),
            )
            self._history[session_id] = response
            return response

        duration_ms = int((time.monotonic() - start) * 1000)
        query_type = (
            final.query_type
            if isinstance(final.query_type, QueryType)
            else QueryType(str(final.query_type))
        )
        response = NLQueryResponse(
            question=final.question,
            sql=final.sql,
            query_type=query_type,
            format=final.output_format,
            results=final.results,
            row_count=len(final.results),
            summary=final.summary,
            markdown=final.markdown,
            source=final.sql_source,
            error=final.error,
            duration_ms=duration_ms,
        )
        self._history[session_id] = response
        logger.info(
            "nl_query_runner.completed",
            session_id=session_id,
            source=response.source,
            rows=response.row_count,
        )
        return response

    def get_history(self) -> list[NLQueryResponse]:
        """Return the last 50 responses (oldest → newest)."""
        return list(self._history.values())[-50:]
