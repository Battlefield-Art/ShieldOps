"""Dynatrace Observability Integration.

Endpoints:
- Metrics: POST /api/v2/metrics/ingest (Dynatrace line protocol)
- Logs: POST /api/v2/logs/ingest (JSON array)
- Traces: OTLP via POST /api/v2/otlp/v1/traces (Protobuf or JSON)
- Events: POST /api/v2/events/ingest

Auth: Api-Token header with scope: metrics.ingest, logs.ingest, openTelemetryTrace.ingest

Base URL: https://{environment-id}.live.dynatrace.com
"""

from __future__ import annotations

import time
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class DynatraceMetric(BaseModel):
    """Dynatrace metric in MINT (line protocol) format.

    MINT format: ``metric.key,dim1=v1,dim2=v2 gauge,42.0 1700000000000``

    Dimension values containing spaces, commas, or equals signs are
    quoted automatically.
    """

    key: str  # e.g., "shieldops.agent.duration"
    value: float
    dimensions: dict[str, str] = Field(default_factory=dict)
    timestamp_ms: int = Field(default_factory=lambda: int(time.time() * 1000))

    def to_line_protocol(self) -> str:
        """Convert to Dynatrace MINT line protocol.

        Format: ``key,dim1=val1,dim2=val2 gauge,value timestamp``

        Special characters in dimension values are escaped per the MINT spec:
        backslash, comma, equals, and double-quote.
        """
        dims = ",".join(f"{k}={_escape_dim_value(v)}" for k, v in sorted(self.dimensions.items()))
        metric_key = f"{self.key},{dims}" if dims else self.key
        return f"{metric_key} gauge,{self.value} {self.timestamp_ms}"


class DynatraceLogEntry(BaseModel):
    """A single Dynatrace log entry for POST /api/v2/logs/ingest."""

    content: str
    log_source: str = "shieldops"
    log_level: str = "INFO"  # NONE, ERROR, WARN, INFO, DEBUG
    dt_entity_host_id: str = ""
    timestamp: str = ""  # ISO 8601
    attributes: dict[str, str] = Field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        """Convert to the JSON dict expected by the Dynatrace log ingest API."""
        payload: dict[str, Any] = {
            "content": self.content,
            "log.source": self.log_source,
            "severity": self.log_level,
        }
        if self.dt_entity_host_id:
            payload["dt.entity.host"] = self.dt_entity_host_id
        if self.timestamp:
            payload["timestamp"] = self.timestamp
        for k, v in self.attributes.items():
            payload[k] = v
        return payload


class DynatraceEvent(BaseModel):
    """A custom Dynatrace event for POST /api/v2/events/ingest."""

    eventType: str = "CUSTOM_INFO"  # CUSTOM_INFO, CUSTOM_ALERT, ERROR_EVENT, etc.
    title: str
    properties: dict[str, str] = Field(default_factory=dict)
    entitySelector: str = ""
    startTime: int = Field(default_factory=lambda: int(time.time() * 1000))
    endTime: int = 0

    def to_payload(self) -> dict[str, Any]:
        """Convert to the JSON dict expected by the events ingest API."""
        payload: dict[str, Any] = {
            "eventType": self.eventType,
            "title": self.title,
            "properties": self.properties,
            "startTime": self.startTime,
        }
        if self.entitySelector:
            payload["entitySelector"] = self.entitySelector
        if self.endTime:
            payload["endTime"] = self.endTime
        return payload


class DynatraceClient:
    """Send telemetry to Dynatrace.

    Endpoints:
    - POST /api/v2/metrics/ingest -- metrics (MINT line protocol, text/plain)
    - POST /api/v2/logs/ingest -- logs (JSON array)
    - POST /api/v2/events/ingest -- custom events (JSON)
    - POST /api/v2/otlp/v1/traces -- traces (OTLP JSON)

    When ``_token`` is empty the client operates in **buffered/test mode**:
    data is stored locally instead of being sent over HTTP.
    """

    def __init__(
        self,
        environment_id: str = "",
        api_token: str = "",
        base_url: str = "",
    ):
        self._env_id = environment_id
        self._token = api_token
        self._base_url = base_url or f"https://{environment_id}.live.dynatrace.com"
        self._buffer: dict[str, list[Any]] = {
            "metrics": [],
            "logs": [],
            "events": [],
            "traces": [],
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self, content_type: str = "application/json") -> dict[str, str]:
        return {
            "Authorization": f"Api-Token {self._token}",
            "Content-Type": content_type,
        }

    async def _post(
        self,
        path: str,
        payload: Any,
        content_type: str = "application/json",
    ) -> dict[str, Any]:
        """POST to the Dynatrace API.

        In production this uses ``httpx.AsyncClient``.  When no token is
        configured the data is buffered locally for inspection in tests.
        """
        url = f"{self._base_url}{path}"

        if not self._token:
            bucket = _path_to_bucket(path)
            if isinstance(payload, list):
                self._buffer[bucket].extend(payload)
                count = len(payload)
            else:
                self._buffer[bucket].append(payload)
                count = 1
            logger.debug(
                "dynatrace_ingest_buffered",
                path=path,
                count=count,
                bucket=bucket,
            )
            return {"status": "buffered", "count": count}

        # Production path -- use httpx (imported lazily so tests don't need it).
        try:
            import httpx  # noqa: WPS433

            async with httpx.AsyncClient() as client:
                kwargs: dict[str, Any] = {
                    "headers": self._headers(content_type),
                    "timeout": 30.0,
                }
                if content_type == "text/plain":
                    kwargs["content"] = payload if isinstance(payload, str) else str(payload)
                else:
                    kwargs["json"] = payload

                resp = await client.post(url, **kwargs)
                resp.raise_for_status()
                logger.info(
                    "dynatrace_ingest_ok",
                    path=path,
                    status=resp.status_code,
                )
                return {
                    "status": "ok",
                    "http_status": resp.status_code,
                    "count": len(payload) if isinstance(payload, list) else 1,
                }
        except Exception as exc:
            logger.error("dynatrace_ingest_error", path=path, error=str(exc))
            return {"status": "error", "error": str(exc), "count": 0}

    # ------------------------------------------------------------------
    # Public API -- raw send
    # ------------------------------------------------------------------

    async def send_metrics(self, metrics: list[DynatraceMetric]) -> dict[str, Any]:
        """Send metrics to POST /api/v2/metrics/ingest.

        The ingest API expects newline-separated MINT lines with
        ``Content-Type: text/plain; charset=utf-8``.
        """
        lines = [m.to_line_protocol() for m in metrics]
        body = "\n".join(lines)

        # For buffered mode we store the structured data, not the raw text.
        if not self._token:
            self._buffer["metrics"].extend([m.model_dump() for m in metrics])
            logger.debug(
                "dynatrace_ingest_buffered", path="/api/v2/metrics/ingest", count=len(metrics)
            )
            return {"status": "buffered", "count": len(metrics)}

        return await self._post(
            "/api/v2/metrics/ingest",
            body,
            content_type="text/plain; charset=utf-8",
        )

    async def send_logs(self, logs: list[DynatraceLogEntry]) -> dict[str, Any]:
        """Send logs to POST /api/v2/logs/ingest (JSON array)."""
        payload = [entry.to_payload() for entry in logs]
        return await self._post("/api/v2/logs/ingest", payload)

    async def send_events(self, events: list[DynatraceEvent]) -> dict[str, Any]:
        """Send events to POST /api/v2/events/ingest."""
        payload = [evt.to_payload() for evt in events]
        return await self._post("/api/v2/events/ingest", payload)

    async def send_traces(self, spans: list[dict[str, Any]]) -> dict[str, Any]:
        """Send OTLP trace spans to POST /api/v2/otlp/v1/traces.

        Expects pre-formatted OTLP JSON resource spans.
        """
        payload = {"resourceSpans": spans}
        return await self._post("/api/v2/otlp/v1/traces", payload)

    # ------------------------------------------------------------------
    # Convenience -- agent-level helpers
    # ------------------------------------------------------------------

    async def send_agent_metric(
        self,
        agent_type: str,
        metric_name: str,
        value: float,
        dims: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a single agent metric with standard ShieldOps dimensions."""
        dimensions = {"agent_type": agent_type, "platform": "shieldops"}
        if dims:
            dimensions.update(dims)
        metric = DynatraceMetric(
            key=f"shieldops.agent.{metric_name}",
            value=value,
            dimensions=dimensions,
        )
        return await self.send_metrics([metric])

    async def send_agent_log(
        self,
        agent_type: str,
        level: str,
        message: str,
        attrs: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a single agent log entry."""
        attributes = {"agent_type": agent_type, "platform": "shieldops"}
        if attrs:
            attributes.update(attrs)
        entry = DynatraceLogEntry(
            content=message,
            log_source=f"shieldops.{agent_type}",
            log_level=level,
            attributes=attributes,
        )
        return await self.send_logs([entry])

    async def send_agent_event(
        self,
        agent_type: str,
        title: str,
        event_type: str = "CUSTOM_INFO",
        props: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a single agent custom event."""
        properties = {"agent_type": agent_type, "platform": "shieldops"}
        if props:
            properties.update(props)
        event = DynatraceEvent(
            eventType=event_type,
            title=title,
            properties=properties,
        )
        return await self.send_events([event])

    # ------------------------------------------------------------------
    # Buffer management
    # ------------------------------------------------------------------

    def get_buffered(self) -> dict[str, list[Any]]:
        """Get buffered data (for local/test mode when no token is set)."""
        return self._buffer

    def clear_buffer(self) -> None:
        """Clear all buffered data."""
        self._buffer = {"metrics": [], "logs": [], "events": [], "traces": []}


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------


def _escape_dim_value(value: str) -> str:
    """Escape special characters in a MINT dimension value.

    Per the Dynatrace MINT spec, backslash, comma, equals sign,
    and double-quote must be escaped with a leading backslash.
    Spaces are allowed in dimension values without escaping.
    """
    value = value.replace("\\", "\\\\")
    value = value.replace(",", "\\,")
    value = value.replace("=", "\\=")
    value = value.replace('"', '\\"')
    return value


def _path_to_bucket(path: str) -> str:
    """Map an API path to its buffer bucket name."""
    if "metrics" in path:
        return "metrics"
    if "logs" in path:
        return "logs"
    if "event" in path:
        return "events"
    if "trace" in path or "otlp" in path:
        return "traces"
    return "metrics"
