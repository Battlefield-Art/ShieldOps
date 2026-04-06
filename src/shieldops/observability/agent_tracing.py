"""Agent-level OpenTelemetry tracing for ShieldOps.

Provides helper functions to create hierarchical spans for agent execution:
agent root span -> node spans -> connector / LLM child spans.

Graceful degradation: if OpenTelemetry SDK is not installed, all functions
return no-op context managers that record nothing.

Usage::

    from shieldops.observability.agent_tracing import (
        start_agent_span,
        start_node_span,
        start_connector_span,
        start_llm_span,
    )

    with start_agent_span("investigation", {"alert_id": "a-123"}) as agent_span:
        with start_node_span(agent_span, "gather_logs") as node_span:
            with start_connector_span(node_span, "splunk", "search"):
                ...
            with start_llm_span(node_span, "claude-sonnet-4-20250514", 1200, 450):
                ...
"""

from __future__ import annotations

import contextlib
import time
from collections import deque
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()

# ── OTel availability detection ─────────────────────────────────────

try:
    from opentelemetry import trace
    from opentelemetry.trace import StatusCode, Tracer

    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False


def _get_tracer(name: str = "shieldops.agents") -> Tracer | None:
    """Return a tracer if OTel is available, else ``None``."""
    if not _OTEL_AVAILABLE:
        return None
    return trace.get_tracer(name)


# ── In-memory trace store for the /traces API ───────────────────────

_MAX_STORED_TRACES = 1000


@dataclass
class SpanRecord:
    """Lightweight record of a completed span for API exposure."""

    trace_id: str
    span_id: str
    parent_span_id: str
    name: str
    kind: str  # "agent", "node", "connector", "llm"
    start_time_ns: int
    end_time_ns: int = 0
    attributes: dict[str, Any] = field(default_factory=dict)
    status: str = "OK"
    children: list[SpanRecord] = field(default_factory=list)


@dataclass
class TraceRecord:
    """A full trace comprising one agent execution."""

    trace_id: str
    agent_name: str
    start_time_ns: int
    end_time_ns: int = 0
    status: str = "OK"
    root_span: SpanRecord | None = None
    spans: list[SpanRecord] = field(default_factory=list)


class TraceStore:
    """Ring-buffer store for recent agent traces."""

    def __init__(self, max_traces: int = _MAX_STORED_TRACES) -> None:
        self._traces: deque[TraceRecord] = deque(maxlen=max_traces)
        self._index: dict[str, TraceRecord] = {}

    def add_trace(self, record: TraceRecord) -> None:
        """Add a completed trace record."""
        if len(self._traces) == self._traces.maxlen and self._traces:
            evicted = self._traces[0]
            self._index.pop(evicted.trace_id, None)
        self._traces.append(record)
        self._index[record.trace_id] = record

    def get_trace(self, trace_id: str) -> TraceRecord | None:
        """Retrieve a trace by ID."""
        return self._index.get(trace_id)

    def list_traces(
        self,
        agent_name: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[TraceRecord]:
        """List traces with optional filtering and pagination."""
        results: list[TraceRecord] = []
        for tr in reversed(self._traces):
            if agent_name and tr.agent_name != agent_name:
                continue
            if status and tr.status != status:
                continue
            results.append(tr)

        return results[offset : offset + limit]

    def count(
        self,
        agent_name: str | None = None,
        status: str | None = None,
    ) -> int:
        """Count traces matching the given filters."""
        total = 0
        for tr in self._traces:
            if agent_name and tr.agent_name != agent_name:
                continue
            if status and tr.status != status:
                continue
            total += 1
        return total

    def clear(self) -> None:
        """Clear all stored traces."""
        self._traces.clear()
        self._index.clear()


# Module-level singleton
_store: TraceStore | None = None


def get_trace_store() -> TraceStore:
    """Return the module-level trace store singleton."""
    global _store  # noqa: PLW0603
    if _store is None:
        _store = TraceStore()
    return _store


def reset_trace_store() -> None:
    """Destroy the singleton (useful in tests)."""
    global _store  # noqa: PLW0603
    _store = None


# ── Span helper utilities ───────────────────────────────────────────


def _span_id_hex(span: Any) -> str:
    """Extract hex span ID from an OTel span."""
    if _OTEL_AVAILABLE and hasattr(span, "get_span_context"):
        ctx = span.get_span_context()
        return format(ctx.span_id, "016x")
    return ""


def _trace_id_hex(span: Any) -> str:
    """Extract hex trace ID from an OTel span."""
    if _OTEL_AVAILABLE and hasattr(span, "get_span_context"):
        ctx = span.get_span_context()
        return format(ctx.trace_id, "032x")
    return ""


def _time_ns() -> int:
    return time.time_ns()


# ── Public span creation functions ──────────────────────────────────


@contextmanager
def start_agent_span(
    agent_name: str,
    input_data: dict[str, Any] | None = None,
) -> Generator[Any, None, None]:
    """Create a root OTel span for an agent execution.

    Also records the trace in the in-memory TraceStore for the API.

    Args:
        agent_name: Name of the agent (e.g. ``investigation``).
        input_data: Optional dict of input attributes to attach to the span.

    Yields:
        The OTel span (or a no-op object if OTel is unavailable).
    """
    store = get_trace_store()
    start_ns = _time_ns()
    tracer = _get_tracer()

    if tracer is None:
        # No-op path: yield a simple namespace so callers can still use it
        noop = _NoOpSpan(agent_name=agent_name)
        trace_record = TraceRecord(
            trace_id=noop.noop_trace_id,
            agent_name=agent_name,
            start_time_ns=start_ns,
        )
        root_record = SpanRecord(
            trace_id=noop.noop_trace_id,
            span_id=noop.noop_span_id,
            parent_span_id="",
            name=f"agent.{agent_name}",
            kind="agent",
            start_time_ns=start_ns,
            attributes={"agent.name": agent_name, **(input_data or {})},
        )
        noop._trace_record = trace_record
        noop._span_record = root_record
        try:
            yield noop
            root_record.status = "OK"
            trace_record.status = "OK"
        except Exception:
            root_record.status = "ERROR"
            trace_record.status = "ERROR"
            raise
        finally:
            end_ns = _time_ns()
            root_record.end_time_ns = end_ns
            trace_record.end_time_ns = end_ns
            trace_record.root_span = root_record
            trace_record.spans.insert(0, root_record)
            store.add_trace(trace_record)
        return

    # OTel path
    with tracer.start_as_current_span(f"agent.{agent_name}") as span:
        span.set_attribute("agent.name", agent_name)
        span.set_attribute("agent.type", "langgraph")
        if input_data:
            for key, val in input_data.items():
                with contextlib.suppress(Exception):
                    span.set_attribute(f"agent.input.{key}", str(val))

        trace_id = _trace_id_hex(span)
        span_id = _span_id_hex(span)

        trace_record = TraceRecord(
            trace_id=trace_id,
            agent_name=agent_name,
            start_time_ns=start_ns,
        )
        root_record = SpanRecord(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id="",
            name=f"agent.{agent_name}",
            kind="agent",
            start_time_ns=start_ns,
            attributes={"agent.name": agent_name, **(input_data or {})},
        )

        # Attach store refs to span for child span recording
        span._shieldops_trace_record = trace_record  # type: ignore[attr-defined]
        span._shieldops_span_record = root_record  # type: ignore[attr-defined]

        try:
            yield span
            root_record.status = "OK"
            trace_record.status = "OK"
        except Exception:
            span.set_status(StatusCode.ERROR)
            root_record.status = "ERROR"
            trace_record.status = "ERROR"
            raise
        finally:
            end_ns = _time_ns()
            root_record.end_time_ns = end_ns
            trace_record.end_time_ns = end_ns
            trace_record.root_span = root_record
            trace_record.spans.insert(0, root_record)
            store.add_trace(trace_record)


@contextmanager
def start_node_span(
    parent: Any,
    node_name: str,
) -> Generator[Any, None, None]:
    """Create a child span for a graph node execution.

    Args:
        parent: The parent span (from ``start_agent_span``).
        node_name: Name of the graph node.

    Yields:
        The OTel child span or a no-op object.
    """
    start_ns = _time_ns()
    tracer = _get_tracer()

    trace_record = _get_trace_record(parent)
    parent_span_id = _get_span_id(parent)
    trace_id = _get_trace_id(parent)

    span_record = SpanRecord(
        trace_id=trace_id,
        span_id="",
        parent_span_id=parent_span_id,
        name=f"node.{node_name}",
        kind="node",
        start_time_ns=start_ns,
        attributes={"node.name": node_name},
    )

    if tracer is None:
        noop = _NoOpSpan(agent_name=node_name)
        noop._span_record = span_record
        noop._trace_record = trace_record
        span_record.span_id = noop.noop_span_id
        try:
            yield noop
            span_record.status = "OK"
        except Exception:
            span_record.status = "ERROR"
            raise
        finally:
            span_record.end_time_ns = _time_ns()
            if trace_record:
                trace_record.spans.append(span_record)
        return

    with tracer.start_as_current_span(f"node.{node_name}") as span:
        span.set_attribute("node.name", node_name)
        span_record.span_id = _span_id_hex(span)
        span._shieldops_trace_record = trace_record  # type: ignore[attr-defined]
        span._shieldops_span_record = span_record  # type: ignore[attr-defined]
        try:
            yield span
            span_record.status = "OK"
        except Exception:
            span.set_status(StatusCode.ERROR)
            span_record.status = "ERROR"
            raise
        finally:
            span_record.end_time_ns = _time_ns()
            if trace_record:
                trace_record.spans.append(span_record)


@contextmanager
def start_connector_span(
    parent: Any,
    connector: str,
    method: str,
) -> Generator[Any, None, None]:
    """Create a child span for a connector call.

    Args:
        parent: The parent span.
        connector: Connector name (e.g. ``splunk``, ``crowdstrike``).
        method: Method being called (e.g. ``search``, ``get_detections``).

    Yields:
        The OTel child span or a no-op object.
    """
    start_ns = _time_ns()
    tracer = _get_tracer()

    trace_record = _get_trace_record(parent)
    parent_span_id = _get_span_id(parent)
    trace_id = _get_trace_id(parent)

    span_record = SpanRecord(
        trace_id=trace_id,
        span_id="",
        parent_span_id=parent_span_id,
        name=f"connector.{connector}.{method}",
        kind="connector",
        start_time_ns=start_ns,
        attributes={"connector.name": connector, "connector.method": method},
    )

    if tracer is None:
        noop = _NoOpSpan(agent_name=f"{connector}.{method}")
        noop._span_record = span_record
        noop._trace_record = trace_record
        span_record.span_id = noop.noop_span_id
        try:
            yield noop
            span_record.status = "OK"
        except Exception:
            span_record.status = "ERROR"
            raise
        finally:
            span_record.end_time_ns = _time_ns()
            if trace_record:
                trace_record.spans.append(span_record)
        return

    with tracer.start_as_current_span(f"connector.{connector}.{method}") as span:
        span.set_attribute("connector.name", connector)
        span.set_attribute("connector.method", method)
        span_record.span_id = _span_id_hex(span)
        span._shieldops_trace_record = trace_record  # type: ignore[attr-defined]
        span._shieldops_span_record = span_record  # type: ignore[attr-defined]
        try:
            yield span
            span_record.status = "OK"
        except Exception:
            span.set_status(StatusCode.ERROR)
            span_record.status = "ERROR"
            raise
        finally:
            span_record.end_time_ns = _time_ns()
            if trace_record:
                trace_record.spans.append(span_record)


@contextmanager
def start_llm_span(
    parent: Any,
    model: str,
    tokens_in: int = 0,
    tokens_out: int = 0,
) -> Generator[Any, None, None]:
    """Create a child span for an LLM call.

    Args:
        parent: The parent span.
        model: Model identifier (e.g. ``claude-sonnet-4-20250514``).
        tokens_in: Number of input tokens.
        tokens_out: Number of output tokens.

    Yields:
        The OTel child span or a no-op object.
    """
    start_ns = _time_ns()
    tracer = _get_tracer()

    trace_record = _get_trace_record(parent)
    parent_span_id = _get_span_id(parent)
    trace_id = _get_trace_id(parent)

    span_record = SpanRecord(
        trace_id=trace_id,
        span_id="",
        parent_span_id=parent_span_id,
        name=f"llm.{model}",
        kind="llm",
        start_time_ns=start_ns,
        attributes={
            "llm.model": model,
            "llm.tokens_in": tokens_in,
            "llm.tokens_out": tokens_out,
        },
    )

    if tracer is None:
        noop = _NoOpSpan(agent_name=model)
        noop._span_record = span_record
        noop._trace_record = trace_record
        span_record.span_id = noop.noop_span_id
        try:
            yield noop
            span_record.status = "OK"
        except Exception:
            span_record.status = "ERROR"
            raise
        finally:
            span_record.end_time_ns = _time_ns()
            if trace_record:
                trace_record.spans.append(span_record)
        return

    with tracer.start_as_current_span(f"llm.{model}") as span:
        span.set_attribute("llm.model", model)
        span.set_attribute("llm.tokens_in", tokens_in)
        span.set_attribute("llm.tokens_out", tokens_out)
        span_record.span_id = _span_id_hex(span)
        span._shieldops_trace_record = trace_record  # type: ignore[attr-defined]
        span._shieldops_span_record = span_record  # type: ignore[attr-defined]
        try:
            yield span
            span_record.status = "OK"
        except Exception:
            span.set_status(StatusCode.ERROR)
            span_record.status = "ERROR"
            raise
        finally:
            span_record.end_time_ns = _time_ns()
            if trace_record:
                trace_record.spans.append(span_record)


# ── Internal helpers ────────────────────────────────────────────────


def _get_trace_record(span: Any) -> TraceRecord | None:
    """Extract the TraceRecord attached to a span."""
    return getattr(span, "_shieldops_trace_record", None) or getattr(span, "_trace_record", None)


def _get_span_id(span: Any) -> str:
    """Get the span ID from an OTel span or no-op span."""
    if hasattr(span, "noop_span_id"):
        return span.noop_span_id
    return _span_id_hex(span)


def _get_trace_id(span: Any) -> str:
    """Get the trace ID from an OTel span or no-op span."""
    if hasattr(span, "noop_trace_id"):
        return span.noop_trace_id
    return _trace_id_hex(span)


class _NoOpSpan:
    """Minimal stand-in when OpenTelemetry is not available.

    Provides ``set_attribute`` and ``set_status`` as no-ops, plus
    stable IDs for trace/span correlation in the store.
    """

    def __init__(self, agent_name: str = "") -> None:
        import uuid

        self.noop_trace_id = uuid.uuid4().hex
        self.noop_span_id = uuid.uuid4().hex[:16]
        self._agent_name = agent_name
        self._trace_record: TraceRecord | None = None
        self._span_record: SpanRecord | None = None

    def set_attribute(self, key: str, value: Any) -> None:
        """No-op attribute setter."""

    def set_status(self, *args: Any, **kwargs: Any) -> None:
        """No-op status setter."""

    def get_span_context(self) -> None:
        """No-op span context."""
        return None
