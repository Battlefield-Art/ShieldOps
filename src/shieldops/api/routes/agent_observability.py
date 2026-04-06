"""Agent observability API routes — metrics and traces.

Exposes Prometheus-format metrics and recent agent trace data for
operational monitoring.

Endpoints:
    GET /api/v1/observability/metrics  — Prometheus text exposition format
    GET /api/v1/observability/traces   — paginated trace listing
    GET /api/v1/observability/traces/{trace_id} — single trace detail with span tree
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from shieldops.api.middleware.metrics import get_metrics_registry
from shieldops.observability.agent_tracing import (
    SpanRecord,
    TraceRecord,
    get_trace_store,
)

logger = structlog.get_logger()

router = APIRouter(
    prefix="/observability",
    tags=["Agent Observability"],
)


# ── Response models ─────────────────────────────────────────────────


class SpanResponse(BaseModel):
    """Serialisable representation of a single span."""

    trace_id: str
    span_id: str
    parent_span_id: str
    name: str
    kind: str
    start_time_ns: int
    end_time_ns: int
    duration_ms: float = 0.0
    attributes: dict[str, Any] = Field(default_factory=dict)
    status: str = "OK"

    model_config = {"extra": "forbid"}


class TraceResponse(BaseModel):
    """Serialisable representation of a full trace."""

    trace_id: str
    agent_name: str
    start_time_ns: int
    end_time_ns: int
    duration_ms: float = 0.0
    status: str = "OK"
    span_count: int = 0

    model_config = {"extra": "forbid"}


class TraceDetailResponse(BaseModel):
    """Full trace with nested span tree."""

    trace_id: str
    agent_name: str
    start_time_ns: int
    end_time_ns: int
    duration_ms: float = 0.0
    status: str = "OK"
    spans: list[SpanResponse] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


class TraceListResponse(BaseModel):
    """Paginated trace listing."""

    traces: list[TraceResponse]
    total: int
    limit: int
    offset: int

    model_config = {"extra": "forbid"}


# ── Helpers ─────────────────────────────────────────────────────────


def _span_to_response(record: SpanRecord) -> SpanResponse:
    duration_ms = (
        (record.end_time_ns - record.start_time_ns) / 1_000_000 if record.end_time_ns > 0 else 0.0
    )
    return SpanResponse(
        trace_id=record.trace_id,
        span_id=record.span_id,
        parent_span_id=record.parent_span_id,
        name=record.name,
        kind=record.kind,
        start_time_ns=record.start_time_ns,
        end_time_ns=record.end_time_ns,
        duration_ms=round(duration_ms, 3),
        attributes=record.attributes,
        status=record.status,
    )


def _trace_to_response(record: TraceRecord) -> TraceResponse:
    duration_ms = (
        (record.end_time_ns - record.start_time_ns) / 1_000_000 if record.end_time_ns > 0 else 0.0
    )
    return TraceResponse(
        trace_id=record.trace_id,
        agent_name=record.agent_name,
        start_time_ns=record.start_time_ns,
        end_time_ns=record.end_time_ns,
        duration_ms=round(duration_ms, 3),
        status=record.status,
        span_count=len(record.spans),
    )


def _trace_to_detail(record: TraceRecord) -> TraceDetailResponse:
    duration_ms = (
        (record.end_time_ns - record.start_time_ns) / 1_000_000 if record.end_time_ns > 0 else 0.0
    )
    return TraceDetailResponse(
        trace_id=record.trace_id,
        agent_name=record.agent_name,
        start_time_ns=record.start_time_ns,
        end_time_ns=record.end_time_ns,
        duration_ms=round(duration_ms, 3),
        status=record.status,
        spans=[_span_to_response(s) for s in record.spans],
    )


# ── Endpoints ───────────────────────────────────────────────────────


@router.get(
    "/metrics",
    response_class=PlainTextResponse,
    summary="Prometheus metrics",
    description="Returns all agent metrics in Prometheus text exposition format.",
)
async def get_metrics() -> PlainTextResponse:
    """Return Prometheus-format metrics text."""
    registry = get_metrics_registry()
    body = registry.collect()
    return PlainTextResponse(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")


@router.get(
    "/traces",
    response_model=TraceListResponse,
    summary="List recent agent traces",
    description="Paginated, filterable list of recent agent execution traces.",
)
async def list_traces(
    agent_name: str | None = Query(None, description="Filter by agent name"),
    status: str | None = Query(None, description="Filter by status (OK, ERROR)"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
) -> TraceListResponse:
    """List recent traces with optional filtering."""
    store = get_trace_store()
    traces = store.list_traces(
        agent_name=agent_name,
        status=status,
        limit=limit,
        offset=offset,
    )
    total = store.count(agent_name=agent_name, status=status)

    return TraceListResponse(
        traces=[_trace_to_response(t) for t in traces],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/traces/{trace_id}",
    response_model=TraceDetailResponse,
    summary="Trace detail with span tree",
    description="Returns a single trace with all its child spans.",
)
async def get_trace(trace_id: str) -> TraceDetailResponse:
    """Return a single trace with its full span tree."""
    store = get_trace_store()
    record = store.get_trace(trace_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Trace {trace_id} not found")
    return _trace_to_detail(record)
