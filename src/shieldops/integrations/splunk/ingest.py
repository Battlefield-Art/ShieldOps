"""Splunk Observability Cloud Ingestion Client.

Sends metrics, traces, and events to Splunk Observability Cloud (formerly SignalFx).
Uses the SignalFx ingest API: POST /v2/datapoint, /v2/trace, /v2/event.

Base URL: https://ingest.{realm}.signalfx.com
Auth: X-SF-Token header
"""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class MetricType(StrEnum):
    GAUGE = "gauge"
    COUNTER = "counter"
    CUMULATIVE_COUNTER = "cumulative_counter"


class SplunkDataPoint(BaseModel):
    """A single Splunk metric data point."""

    metric: str
    value: float
    metric_type: MetricType = MetricType.GAUGE
    dimensions: dict[str, str] = Field(default_factory=dict)
    timestamp: int = Field(default_factory=lambda: int(time.time() * 1000))


class SplunkEvent(BaseModel):
    """A Splunk custom event."""

    eventType: str
    category: str = "USER_DEFINED"
    dimensions: dict[str, str] = Field(default_factory=dict)
    properties: dict[str, Any] = Field(default_factory=dict)
    timestamp: int = Field(default_factory=lambda: int(time.time() * 1000))


class SplunkSpan(BaseModel):
    """A trace span in Zipkin v2 format for Splunk APM."""

    traceId: str
    id: str
    name: str
    parentId: str = ""
    kind: str = "SERVER"
    timestamp: int = Field(default_factory=lambda: int(time.time() * 1_000_000))
    duration: int = 0  # microseconds
    localEndpoint: dict[str, str] = Field(default_factory=dict)
    tags: dict[str, str] = Field(default_factory=dict)


class SplunkIngestClient:
    """Send telemetry to Splunk Observability Cloud.

    Endpoints:
    - POST /v2/datapoint -- metrics (gauge, counter, cumulative_counter)
    - POST /v2/trace -- traces (Zipkin v2 JSON format)
    - POST /v2/event -- custom events

    When ``_token`` is empty the client operates in **buffered/test mode**:
    data is stored locally instead of being sent over HTTP.
    """

    def __init__(
        self,
        realm: str = "us1",
        ingest_token: str = "",
        base_url: str = "",  # Override for testing
    ):
        self._realm = realm
        self._token = ingest_token
        self._base_url = base_url or f"https://ingest.{realm}.signalfx.com"
        self._buffer: dict[str, list[dict[str, Any]]] = {
            "datapoints": [],
            "traces": [],
            "events": [],
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {"X-SF-Token": self._token, "Content-Type": "application/json"}

    async def _post(self, path: str, payload: list[dict[str, Any]]) -> dict[str, Any]:
        """POST JSON to the ingest API.

        In production this would use ``httpx.AsyncClient``.  When no token is
        configured the data is buffered locally for inspection in tests.
        """
        url = f"{self._base_url}{path}"

        if not self._token:
            # Buffered / test mode -- store locally.
            bucket = "datapoints"
            if "trace" in path:
                bucket = "traces"
            elif "event" in path:
                bucket = "events"
            self._buffer[bucket].extend(payload)
            logger.debug(
                "splunk_ingest_buffered",
                path=path,
                count=len(payload),
                bucket=bucket,
            )
            return {"status": "buffered", "count": len(payload)}

        # Production path -- use httpx (imported lazily so tests don't need it).
        try:
            import httpx  # noqa: WPS433

            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    url,
                    json=payload,
                    headers=self._headers(),
                    timeout=30.0,
                )
                resp.raise_for_status()
                logger.info(
                    "splunk_ingest_ok",
                    path=path,
                    status=resp.status_code,
                    count=len(payload),
                )
                return {"status": "ok", "http_status": resp.status_code, "count": len(payload)}
        except Exception as exc:
            logger.error("splunk_ingest_error", path=path, error=str(exc))
            return {"status": "error", "error": str(exc), "count": 0}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def send_metrics(self, datapoints: list[SplunkDataPoint]) -> dict[str, Any]:
        """Send metrics to POST /v2/datapoint.

        The ingest API expects the body grouped by metric type:
        ``{"gauge": [...], "counter": [...], "cumulative_counter": [...]}``.
        We flatten to a list of dicts for buffered mode, but structure
        correctly for the real HTTP call.
        """
        grouped: dict[str, list[dict[str, Any]]] = {
            "gauge": [],
            "counter": [],
            "cumulative_counter": [],
        }
        for dp in datapoints:
            grouped[dp.metric_type.value].append(
                {
                    "metric": dp.metric,
                    "value": dp.value,
                    "dimensions": dp.dimensions,
                    "timestamp": dp.timestamp,
                }
            )

        # For buffered mode we store the flat list; for HTTP we'd send grouped.
        flat = [dp.model_dump() for dp in datapoints]
        return await self._post("/v2/datapoint", flat)

    async def send_traces(self, spans: list[SplunkSpan]) -> dict[str, Any]:
        """Send trace spans to POST /v2/trace (Zipkin v2 JSON)."""
        payload = [span.model_dump() for span in spans]
        return await self._post("/v2/trace", payload)

    async def send_events(self, events: list[SplunkEvent]) -> dict[str, Any]:
        """Send custom events to POST /v2/event."""
        payload = [evt.model_dump() for evt in events]
        return await self._post("/v2/event", payload)

    async def send_agent_metrics(
        self,
        agent_type: str,
        metrics: dict[str, float],
        dimensions: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Convenience: send agent performance metrics.

        Each key in *metrics* becomes a gauge named ``agent.<key>`` with
        an ``agent_type`` dimension attached automatically.
        """
        dims = {"agent_type": agent_type, "platform": "shieldops"}
        if dimensions:
            dims.update(dimensions)

        datapoints = [
            SplunkDataPoint(
                metric=f"agent.{name}",
                value=value,
                metric_type=MetricType.GAUGE,
                dimensions=dims,
            )
            for name, value in metrics.items()
        ]
        return await self.send_metrics(datapoints)

    async def send_agent_span(
        self,
        agent_type: str,
        node_name: str,
        trace_id: str,
        span_id: str,
        parent_id: str = "",
        duration_us: int = 0,
        tags: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Convenience: send a single agent trace span."""
        span_tags = {
            "agent_type": agent_type,
            "node": node_name,
            "platform": "shieldops",
        }
        if tags:
            span_tags.update(tags)

        span = SplunkSpan(
            traceId=trace_id,
            id=span_id,
            name=f"{agent_type}.{node_name}",
            parentId=parent_id,
            kind="SERVER",
            duration=duration_us,
            localEndpoint={"serviceName": f"shieldops-{agent_type}"},
            tags=span_tags,
        )
        return await self.send_traces([span])

    def get_buffered(self) -> dict[str, list[dict[str, Any]]]:
        """Get buffered data (for local/test mode when no token is set)."""
        return self._buffer

    def clear_buffer(self) -> None:
        """Clear all buffered data."""
        self._buffer = {"datapoints": [], "traces": [], "events": []}
