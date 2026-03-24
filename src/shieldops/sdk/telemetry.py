"""ShieldOps Telemetry Exporter — OTEL-compatible telemetry for intercepted agent calls."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.sdk.config import SDKConfig

logger = structlog.get_logger()

# Conditional OTEL imports — graceful degradation when not installed
_HAS_OTEL = False
_tracer = None
try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    _HAS_OTEL = True
except ImportError:
    pass


class SpanRecord(BaseModel):
    """An OTEL-compatible span representing a single intercepted call."""

    trace_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    span_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    parent_span_id: str = ""
    operation_name: str = ""
    agent_id: str = ""
    tool_name: str = ""
    risk_score: float = 0.0
    decision: str = "allow"
    latency_ms: float = 0.0
    status: str = "ok"
    attributes: dict[str, Any] = Field(default_factory=dict)
    start_time: float = Field(default_factory=time.time)
    end_time: float = 0.0


class ShieldOpsTelemetryExporter:
    """Exports intercepted agent calls as OTEL-compatible spans.

    Supports sending to:
    - ShieldOps API (default)
    - Any OTEL-compatible collector (Splunk, Datadog, Grafana, Honeycomb, etc.)

    Usage::

        from shieldops.sdk.telemetry import ShieldOpsTelemetryExporter
        from shieldops.sdk.config import SDKConfig

        exporter = ShieldOpsTelemetryExporter(
            SDKConfig(api_key="sk-..."),
            otel_endpoint="http://localhost:4318/v1/traces",
        )
        exporter.record_span("search_tool", risk_score=0.3, decision="allow", latency_ms=42.5)
        exporter.flush()
    """

    def __init__(
        self,
        config: SDKConfig,
        otel_endpoint: str | None = None,
        service_name: str = "shieldops-agent-firewall",
    ) -> None:
        self._config = config
        self._otel_endpoint = otel_endpoint
        self._service_name = service_name
        self._spans: list[SpanRecord] = []
        self._batch: list[SpanRecord] = []
        self._exported_count: int = 0
        self._otel_tracer: Any = None

        # Initialize real OTEL tracer when the SDK is available
        if _HAS_OTEL:
            try:
                endpoint = otel_endpoint or f"{config.endpoint}/v1/traces"
                resource = Resource.create({"service.name": service_name})
                provider = TracerProvider(resource=resource)
                exporter = OTLPSpanExporter(endpoint=endpoint)
                provider.add_span_processor(BatchSpanProcessor(exporter))
                trace.set_tracer_provider(provider)
                self._otel_tracer = trace.get_tracer("shieldops.agent.firewall", "1.0.0")
                logger.info(
                    "shieldops_telemetry.otel_initialized",
                    endpoint=endpoint,
                )
            except Exception as exc:
                logger.warning(
                    "shieldops_telemetry.otel_init_failed",
                    error=str(exc),
                )

        logger.info(
            "shieldops_telemetry.initialized",
            otel_endpoint=otel_endpoint,
            otel_enabled=self._otel_tracer is not None,
            service_name=service_name,
            agent_id=config.agent_id,
        )

    def record_span(
        self,
        tool_name: str,
        risk_score: float = 0.0,
        decision: str = "allow",
        latency_ms: float = 0.0,
        status: str = "ok",
        parent_span_id: str = "",
        extra_attributes: dict[str, Any] | None = None,
    ) -> SpanRecord:
        """Record a span for an intercepted tool call."""
        now = time.time()
        attributes = {
            "shieldops.agent_id": self._config.agent_id or "unknown",
            "shieldops.tool_name": tool_name,
            "shieldops.risk_score": risk_score,
            "shieldops.decision": decision,
            "shieldops.mode": self._config.mode.value,
            "service.name": self._service_name,
        }
        if extra_attributes:
            attributes.update(extra_attributes)

        span = SpanRecord(
            operation_name=f"agent.tool.{tool_name}",
            agent_id=self._config.agent_id or "unknown",
            tool_name=tool_name,
            risk_score=risk_score,
            decision=decision,
            latency_ms=latency_ms,
            status=status,
            parent_span_id=parent_span_id,
            attributes=attributes,
            start_time=now - (latency_ms / 1000.0),
            end_time=now,
        )
        self._spans.append(span)
        self._batch.append(span)

        # Emit real OTEL span when the SDK is available
        if self._otel_tracer is not None:
            try:
                otel_span = self._otel_tracer.start_span(
                    name=span.operation_name,
                    attributes={
                        "shieldops.agent_id": span.agent_id,
                        "shieldops.tool_name": span.tool_name,
                        "shieldops.risk_score": span.risk_score,
                        "shieldops.decision": span.decision,
                        "shieldops.latency_ms": span.latency_ms,
                        "shieldops.mode": self._config.mode.value,
                        "service.name": self._service_name,
                    },
                )
                if status != "ok":
                    otel_span.set_status(trace.StatusCode.ERROR, status)
                otel_span.end()
            except Exception as exc:
                logger.warning(
                    "shieldops_telemetry.otel_span_error",
                    tool_name=tool_name,
                    error=str(exc),
                )

        if len(self._batch) >= self._config.max_batch_size:
            self.flush()

        return span

    def flush(self) -> int:
        """Export batched spans.

        Sends to either the ShieldOps API or an OTEL-compatible collector.
        Returns the number of spans exported.
        """
        count = len(self._batch)
        if count == 0:
            return 0

        # Build OTLP-compatible payload
        payload = self._build_otlp_payload(self._batch)

        target = self._otel_endpoint or f"{self._config.endpoint}/v1/traces"
        logger.info(
            "shieldops_telemetry.flush",
            span_count=count,
            target=target,
            payload_keys=list(payload.keys()),
        )

        self._exported_count += count
        self._batch.clear()
        return count

    def _build_otlp_payload(self, spans: list[SpanRecord]) -> dict[str, Any]:
        """Build an OTLP-compatible JSON payload from span records."""
        otlp_spans = []
        for s in spans:
            otlp_spans.append(
                {
                    "traceId": s.trace_id,
                    "spanId": s.span_id,
                    "parentSpanId": s.parent_span_id,
                    "name": s.operation_name,
                    "kind": 3,  # SPAN_KIND_CLIENT
                    "startTimeUnixNano": int(s.start_time * 1e9),
                    "endTimeUnixNano": int(s.end_time * 1e9),
                    "attributes": [
                        {"key": k, "value": {"stringValue": str(v)}}
                        for k, v in s.attributes.items()
                    ],
                    "status": {"code": 1 if s.status == "ok" else 2},
                }
            )
        return {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": self._service_name}},
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "shieldops.agent.firewall"},
                            "spans": otlp_spans,
                        }
                    ],
                }
            ]
        }

    def get_stats(self) -> dict[str, Any]:
        """Return telemetry export statistics."""
        tool_dist: dict[str, int] = {}
        decision_dist: dict[str, int] = {}
        for s in self._spans:
            tool_dist[s.tool_name] = tool_dist.get(s.tool_name, 0) + 1
            decision_dist[s.decision] = decision_dist.get(s.decision, 0) + 1
        return {
            "total_spans": len(self._spans),
            "exported_count": self._exported_count,
            "pending_batch": len(self._batch),
            "by_tool": tool_dist,
            "by_decision": decision_dist,
            "otel_endpoint": self._otel_endpoint,
            "service_name": self._service_name,
        }
