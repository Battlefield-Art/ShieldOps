"""Datadog Observability Integration.

Endpoints:
- Logs: POST https://http-intake.logs.datadoghq.com/api/v2/logs
- Metrics: POST https://api.datadoghq.com/api/v2/series
- Traces: POST https://trace.agent.datadoghq.com/api/v0.2/traces (or OTLP)
Auth: DD-API-KEY header
"""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class DatadogMetricType(StrEnum):
    GAUGE = "gauge"
    RATE = "rate"
    COUNT = "count"


class DatadogLogEntry(BaseModel):
    """A single Datadog log entry."""

    message: str
    ddsource: str = "shieldops"
    ddtags: str = ""
    hostname: str = ""
    service: str = ""
    status: str = "info"
    timestamp: int = Field(default_factory=lambda: int(time.time() * 1000))


class DatadogMetricPoint(BaseModel):
    """A single Datadog metric series payload."""

    metric: str
    type: DatadogMetricType = DatadogMetricType.GAUGE
    points: list[dict[str, Any]] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    unit: str = ""


class DatadogSpan(BaseModel):
    """A single Datadog APM trace span."""

    trace_id: int
    span_id: int
    parent_id: int = 0
    name: str
    service: str = "shieldops"
    resource: str = ""
    type: str = "custom"
    start: int = Field(default_factory=lambda: int(time.time() * 1_000_000_000))
    duration: int = 0  # nanoseconds
    meta: dict[str, str] = Field(default_factory=dict)
    metrics: dict[str, float] = Field(default_factory=dict)


class DatadogClient:
    """Send logs, metrics, and traces to Datadog.

    Endpoints:
    - POST /api/v2/logs          -- structured log entries
    - POST /api/v2/series        -- metric time-series
    - POST /api/v0.2/traces      -- APM trace spans

    When ``_api_key`` is empty the client operates in **buffered/test mode**:
    data is stored locally instead of being sent over HTTP.
    """

    def __init__(
        self,
        api_key: str = "",
        app_key: str = "",
        site: str = "datadoghq.com",
    ):
        self._api_key = api_key
        self._app_key = app_key
        self._site = site
        self._logs_url = f"https://http-intake.logs.{site}/api/v2/logs"
        self._metrics_url = f"https://api.{site}/api/v2/series"
        self._traces_url = f"https://trace.agent.{site}/api/v0.2/traces"
        self._buffer: dict[str, list[dict[str, Any]]] = {
            "logs": [],
            "metrics": [],
            "traces": [],
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        hdrs = {"DD-API-KEY": self._api_key, "Content-Type": "application/json"}
        if self._app_key:
            hdrs["DD-APPLICATION-KEY"] = self._app_key
        return hdrs

    async def _post(self, url: str, payload: Any, bucket: str) -> dict[str, Any]:
        """POST JSON to a Datadog API endpoint.

        In production this uses ``httpx.AsyncClient``.  When no API key is
        configured the data is buffered locally for inspection in tests.
        """
        if not self._api_key:
            # Buffered / test mode -- store locally.
            if isinstance(payload, list):
                self._buffer[bucket].extend(payload)
            else:
                self._buffer[bucket].append(payload)
            logger.debug(
                "datadog_ingest_buffered",
                url=url,
                bucket=bucket,
                count=len(payload) if isinstance(payload, list) else 1,
            )
            return {
                "status": "buffered",
                "count": len(payload) if isinstance(payload, list) else 1,
            }

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
                    "datadog_ingest_ok",
                    url=url,
                    status=resp.status_code,
                    count=len(payload) if isinstance(payload, list) else 1,
                )
                return {
                    "status": "ok",
                    "http_status": resp.status_code,
                    "count": len(payload) if isinstance(payload, list) else 1,
                }
        except Exception as exc:
            logger.error("datadog_ingest_error", url=url, error=str(exc))
            return {"status": "error", "error": str(exc), "count": 0}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def send_logs(self, logs: list[DatadogLogEntry]) -> dict[str, Any]:
        """Send structured log entries to Datadog Logs API.

        POST https://http-intake.logs.{site}/api/v2/logs
        Body: list of log entry objects.
        """
        payload = [log.model_dump() for log in logs]
        return await self._post(self._logs_url, payload, "logs")

    async def send_metrics(self, metrics: list[DatadogMetricPoint]) -> dict[str, Any]:
        """Send metric time-series to Datadog Metrics API.

        POST https://api.{site}/api/v2/series
        Body: ``{"series": [...]}``.
        """
        series = [m.model_dump() for m in metrics]
        payload = {"series": series}
        return await self._post(self._metrics_url, payload, "metrics")

    async def send_traces(self, spans: list[DatadogSpan]) -> dict[str, Any]:
        """Send trace spans to Datadog APM API.

        POST https://trace.agent.{site}/api/v0.2/traces
        Body: list of trace groups (each a list of spans).
        """
        # Group spans by trace_id into trace groups.
        groups: dict[int, list[dict[str, Any]]] = {}
        for span in spans:
            groups.setdefault(span.trace_id, []).append(span.model_dump())
        payload = list(groups.values())
        return await self._post(self._traces_url, payload, "traces")

    async def send_agent_log(
        self,
        agent_type: str,
        level: str,
        message: str,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Convenience: send a single agent log entry."""
        tag_list = [f"agent_type:{agent_type}", "platform:shieldops"]
        if tags:
            tag_list.extend(tags)

        entry = DatadogLogEntry(
            message=message,
            ddsource="shieldops",
            ddtags=",".join(tag_list),
            service=f"shieldops-{agent_type}",
            status=level,
        )
        return await self.send_logs([entry])

    async def send_agent_metric(
        self,
        agent_type: str,
        metric_name: str,
        value: float,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Convenience: send a single agent metric gauge point."""
        tag_list = [f"agent_type:{agent_type}", "platform:shieldops"]
        if tags:
            tag_list.extend(tags)

        now = time.time()
        point = DatadogMetricPoint(
            metric=f"shieldops.agent.{metric_name}",
            type=DatadogMetricType.GAUGE,
            points=[{"timestamp": int(now), "value": value}],
            tags=tag_list,
        )
        return await self.send_metrics([point])

    async def send_agent_span(
        self,
        agent_type: str,
        operation: str,
        trace_id: int,
        span_id: int,
        duration_ns: int = 0,
    ) -> dict[str, Any]:
        """Convenience: send a single agent trace span."""
        span = DatadogSpan(
            trace_id=trace_id,
            span_id=span_id,
            name=f"{agent_type}.{operation}",
            service=f"shieldops-{agent_type}",
            resource=operation,
            type="custom",
            duration=duration_ns,
            meta={
                "agent_type": agent_type,
                "operation": operation,
                "platform": "shieldops",
            },
        )
        return await self.send_traces([span])

    def get_buffered(self) -> dict[str, list[dict[str, Any]]]:
        """Get buffered data (for local/test mode when no API key is set)."""
        return self._buffer

    def clear_buffer(self) -> None:
        """Clear all buffered data."""
        self._buffer = {"logs": [], "metrics": [], "traces": []}
