"""Grafana Tempo Integration — Distributed trace ingestion and querying.

Supports Zipkin v2 JSON format for trace ingestion and TraceQL for querying.

Push API: POST /api/v2/spans (Zipkin v2 JSON)
Query API: GET /api/traces/{traceID}
Search API: GET /api/search (TraceQL)

When no ``username`` is configured the client operates in **buffered/test mode**:
data is stored locally instead of being sent over HTTP.
"""

from __future__ import annotations

import time
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class TempoSpan(BaseModel):
    """A distributed trace span."""

    trace_id: str
    span_id: str
    parent_span_id: str = ""
    operation_name: str
    service_name: str
    start_time_us: int = Field(default_factory=lambda: int(time.time() * 1_000_000))
    duration_us: int = 0
    status: str = "OK"
    attributes: dict[str, str] = Field(default_factory=dict)


class TempoClient:
    """Push traces to Tempo and query by trace ID.

    Endpoints:
    - POST /api/v2/spans — Zipkin v2 JSON trace ingestion
    - GET  /api/traces/{traceID} — retrieve a trace by ID
    - GET  /api/search — search traces using TraceQL

    When ``username`` is empty the client operates in **buffered/test mode**:
    data is stored locally instead of being sent over HTTP.
    """

    def __init__(
        self,
        url: str = "http://localhost:3200",
        tenant_id: str = "shieldops",
        username: str = "",
        password: str = "",
    ):
        self._url = url.rstrip("/")
        self._tenant_id = tenant_id
        self._username = username
        self._password = password
        self._buffer: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-Scope-OrgID": self._tenant_id,
        }

    def _auth(self) -> tuple[str, str] | None:
        if self._username and self._password:
            return (self._username, self._password)
        return None

    async def _post(self, path: str, payload: list[dict[str, Any]]) -> dict[str, Any]:
        """POST JSON to the Tempo API."""
        url = f"{self._url}{path}"

        if not self._username:
            self._buffer.extend(payload)
            logger.debug("tempo_buffered", path=path, span_count=len(payload))
            return {"status": "buffered", "count": len(payload)}

        try:
            import httpx  # noqa: WPS433

            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    url,
                    json=payload,
                    headers=self._headers(),
                    auth=self._auth(),
                    timeout=30.0,
                )
                resp.raise_for_status()
                logger.info("tempo_push_ok", path=path, status=resp.status_code)
                return {"status": "ok", "http_status": resp.status_code, "count": len(payload)}
        except Exception as exc:
            logger.error("tempo_push_error", path=path, error=str(exc))
            return {"status": "error", "error": str(exc), "count": 0}

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET from the Tempo API."""
        url = f"{self._url}{path}"

        if not self._username:
            logger.debug("tempo_query_buffered", path=path)
            return {"status": "buffered", "data": {}}

        try:
            import httpx  # noqa: WPS433

            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    url,
                    params=params or {},
                    headers=self._headers(),
                    auth=self._auth(),
                    timeout=30.0,
                )
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            logger.error("tempo_query_error", path=path, error=str(exc))
            return {"status": "error", "error": str(exc), "data": {}}

    # ------------------------------------------------------------------
    # Internal conversions
    # ------------------------------------------------------------------

    def _span_to_zipkin(self, span: TempoSpan) -> dict[str, Any]:
        """Convert a TempoSpan to Zipkin v2 JSON format."""
        zipkin: dict[str, Any] = {
            "traceId": span.trace_id,
            "id": span.span_id,
            "name": span.operation_name,
            "kind": "SERVER",
            "timestamp": span.start_time_us,
            "duration": span.duration_us,
            "localEndpoint": {"serviceName": span.service_name},
            "tags": {
                "status": span.status,
                **span.attributes,
            },
        }
        if span.parent_span_id:
            zipkin["parentId"] = span.parent_span_id
        return zipkin

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def push_spans(self, spans: list[TempoSpan]) -> dict[str, Any]:
        """Push trace spans to POST /api/v2/spans (Zipkin v2 JSON format)."""
        payload = [self._span_to_zipkin(s) for s in spans]
        return await self._post("/api/v2/spans", payload)

    async def push_agent_span(
        self,
        agent_type: str,
        node_name: str,
        trace_id: str,
        span_id: str,
        parent_id: str = "",
        duration_us: int = 0,
    ) -> dict[str, Any]:
        """Convenience: push a single agent trace span.

        Automatically sets the service name and operation name from the
        agent type and node name.
        """
        span = TempoSpan(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_id,
            operation_name=f"{agent_type}.{node_name}",
            service_name=f"shieldops-{agent_type}",
            duration_us=duration_us,
            attributes={
                "agent_type": agent_type,
                "node": node_name,
                "platform": "shieldops",
            },
        )
        return await self.push_spans([span])

    async def get_trace(self, trace_id: str) -> dict[str, Any]:
        """Get a complete trace by ID from GET /api/traces/{traceID}."""
        return await self._get(f"/api/traces/{trace_id}")

    async def search_traces(
        self,
        service_name: str = "",
        operation: str = "",
        min_duration_ms: int = 0,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Search traces using TraceQL: GET /api/search.

        Builds a TraceQL query from the provided filters.  Returns a list
        of matching traces.  When in buffered mode an empty list is returned.
        """
        conditions: list[str] = []
        if service_name:
            conditions.append(f'resource.service.name = "{service_name}"')
        if operation:
            conditions.append(f'name = "{operation}"')
        if min_duration_ms > 0:
            conditions.append(f"duration > {min_duration_ms}ms")

        traceql = "{ " + " && ".join(conditions) + " }" if conditions else "{}"

        params: dict[str, Any] = {"q": traceql, "limit": str(limit)}
        result = await self._get("/api/search", params)
        return result.get("traces", [])

    def get_buffered(self) -> list[dict[str, Any]]:
        """Get locally buffered spans (when no Tempo credentials configured)."""
        return self._buffer

    def clear_buffer(self) -> None:
        """Clear all buffered data."""
        self._buffer = []
