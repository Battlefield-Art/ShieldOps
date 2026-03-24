"""Honeycomb Observability Integration.

Honeycomb treats observability data as wide structured events rather than
separate logs/metrics/traces. Every event can have hundreds of fields.

Endpoints:
- POST /1/events/{dataset} -- single event
- POST /1/batch/{dataset} -- batch events
- POST /v1/traces -- OTLP traces
Auth: X-Honeycomb-Team header
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class HoneycombEvent(BaseModel):
    """A Honeycomb structured event -- wide, high-cardinality."""

    data: dict[str, Any] = Field(default_factory=dict)
    time: str = ""  # ISO 8601 or RFC3339
    samplerate: int = 1


class HoneycombSpan(BaseModel):
    """A Honeycomb trace span (events with trace context)."""

    name: str
    service_name: str = "shieldops"
    trace_id: str = ""
    span_id: str = ""
    parent_id: str = ""
    duration_ms: float = 0.0
    status: str = "ok"
    attributes: dict[str, Any] = Field(default_factory=dict)


class HoneycombClient:
    """Send wide structured events and traces to Honeycomb.

    Endpoints:
    - POST /1/events/{dataset} -- single event
    - POST /1/batch/{dataset} -- batch of events
    - POST /v1/traces -- OTLP trace spans

    When ``_api_key`` is empty the client operates in **buffered/test mode**:
    data is stored locally instead of being sent over HTTP.
    """

    def __init__(
        self,
        api_key: str = "",
        dataset: str = "shieldops",
        api_url: str = "https://api.honeycomb.io",
    ):
        self._api_key = api_key
        self._dataset = dataset
        self._api_url = api_url
        self._buffer: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {"X-Honeycomb-Team": self._api_key, "Content-Type": "application/json"}

    def _now_iso(self) -> str:
        return datetime.now(UTC).isoformat()

    async def _post(self, path: str, payload: Any) -> dict[str, Any]:
        """POST JSON to the Honeycomb API.

        In production this uses ``httpx.AsyncClient``.  When no API key is
        configured the data is buffered locally for inspection in tests.
        """
        url = f"{self._api_url}{path}"

        if not self._api_key:
            items = payload if isinstance(payload, list) else [payload]
            self._buffer.extend(items)
            logger.debug(
                "honeycomb_buffered",
                path=path,
                count=len(items),
            )
            return {"status": "buffered", "count": len(items)}

        # Production path -- lazy import so tests don't require httpx.
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
                count = len(payload) if isinstance(payload, list) else 1
                logger.info(
                    "honeycomb_ok",
                    path=path,
                    status=resp.status_code,
                    count=count,
                )
                return {"status": "ok", "http_status": resp.status_code, "count": count}
        except Exception as exc:
            logger.error("honeycomb_error", path=path, error=str(exc))
            return {"status": "error", "error": str(exc), "count": 0}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def send_event(self, event: HoneycombEvent) -> dict[str, Any]:
        """POST /1/events/{dataset} -- send a single wide event."""
        payload = event.data.copy()
        if event.time:
            payload["time"] = event.time
        if event.samplerate != 1:
            payload["samplerate"] = event.samplerate
        return await self._post(f"/1/events/{self._dataset}", payload)

    async def send_batch(self, events: list[HoneycombEvent]) -> dict[str, Any]:
        """POST /1/batch/{dataset} -- send a batch of events.

        The batch API expects a list of ``{"data": {...}, "time": "...",
        "samplerate": N}`` objects.
        """
        payload = []
        for evt in events:
            item: dict[str, Any] = {"data": evt.data}
            if evt.time:
                item["time"] = evt.time
            if evt.samplerate != 1:
                item["samplerate"] = evt.samplerate
            payload.append(item)
        return await self._post(f"/1/batch/{self._dataset}", payload)

    async def send_spans(self, spans: list[HoneycombSpan]) -> dict[str, Any]:
        """Send trace spans as Honeycomb events with trace context fields.

        Each span is converted to a wide event enriched with
        ``trace.trace_id``, ``trace.span_id``, ``trace.parent_id``,
        ``service.name``, ``duration_ms``, and ``status``.
        """
        events: list[HoneycombEvent] = []
        for span in spans:
            data: dict[str, Any] = {
                "name": span.name,
                "service.name": span.service_name,
                "trace.trace_id": span.trace_id or uuid.uuid4().hex,
                "trace.span_id": span.span_id or uuid.uuid4().hex[:16],
                "trace.parent_id": span.parent_id,
                "duration_ms": span.duration_ms,
                "status": span.status,
            }
            data.update(span.attributes)
            events.append(HoneycombEvent(data=data, time=self._now_iso()))
        return await self.send_batch(events)

    async def send_agent_event(
        self,
        agent_type: str,
        node_name: str = "",
        duration_ms: float = 0,
        status: str = "ok",
        confidence: float = 0.0,
        reasoning_steps: int = 0,
        llm_tokens: int = 0,
        **extra_fields: Any,
    ) -> dict[str, Any]:
        """Convenience: send a rich ShieldOps agent event.

        Honeycomb excels at high-cardinality data -- include everything:
        agent type, node name, duration, status, confidence, token count,
        plus any extra fields.  This creates powerful query/group-by options
        in Honeycomb's query builder.
        """
        data: dict[str, Any] = {
            "platform": "shieldops",
            "type": "agent_event",
            "agent.type": agent_type,
            "agent.node_name": node_name,
            "agent.status": status,
            "agent.confidence": confidence,
            "agent.reasoning_steps": reasoning_steps,
            "agent.llm_tokens": llm_tokens,
            "duration_ms": duration_ms,
            "service.name": f"shieldops-{agent_type}",
            "environment": extra_fields.pop("environment", "production"),
            "timestamp_epoch_ms": int(time.time() * 1000),
        }
        data.update(extra_fields)

        event = HoneycombEvent(data=data, time=self._now_iso())
        return await self.send_event(event)

    async def send_agent_trace(
        self,
        agent_type: str,
        request_id: str,
        nodes: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Send a complete agent execution as a Honeycomb trace.

        Each node becomes a span.  The full agent run is the root span.
        Total duration is computed from the sum of node durations.
        """
        trace_id = request_id or uuid.uuid4().hex
        root_span_id = uuid.uuid4().hex[:16]

        total_duration = sum(float(n.get("duration_ms", 0)) for n in nodes)

        spans: list[HoneycombSpan] = []

        # Root span for the full agent execution.
        spans.append(
            HoneycombSpan(
                name=f"{agent_type}.execution",
                service_name=f"shieldops-{agent_type}",
                trace_id=trace_id,
                span_id=root_span_id,
                parent_id="",
                duration_ms=total_duration,
                status="ok",
                attributes={
                    "agent.type": agent_type,
                    "agent.node_count": len(nodes),
                    "platform": "shieldops",
                    "type": "agent_trace",
                },
            )
        )

        # Child spans for each node.
        for node in nodes:
            spans.append(
                HoneycombSpan(
                    name=f"{agent_type}.{node.get('name', 'unknown')}",
                    service_name=f"shieldops-{agent_type}",
                    trace_id=trace_id,
                    span_id=uuid.uuid4().hex[:16],
                    parent_id=root_span_id,
                    duration_ms=float(node.get("duration_ms", 0)),
                    status=node.get("status", "ok"),
                    attributes={
                        k: v for k, v in node.items() if k not in ("name", "duration_ms", "status")
                    },
                )
            )

        return await self.send_spans(spans)

    def get_buffered(self) -> list[dict[str, Any]]:
        """Get buffered data (for local/test mode when no API key is set)."""
        return self._buffer

    def clear_buffer(self) -> None:
        """Clear all buffered data."""
        self._buffer = []
