"""OTLP/HTTP log receiver.

Accepts OpenTelemetry log records over HTTP (JSON or Protobuf) at
``POST /api/v1/ingest/otlp/logs`` and pushes them through the ingestion
pipeline with ``source_provider="otel"``.

Wire format reference: https://opentelemetry.io/docs/specs/otlp/#otlphttp
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from shieldops.ingestion.otlp.parser import (
    otlp_http_json_to_events,
    otlp_http_protobuf_to_events,
)
from shieldops.ingestion.pipeline import process_batch

logger = structlog.get_logger()

router = APIRouter(prefix="/ingest/otlp", tags=["OTLP Ingestion"])


class OTLPLogsResponse(BaseModel):
    """Response for OTLP log ingestion."""

    status: str = "accepted"
    source: str = "otel"
    events_accepted: int = 0
    events_rejected: int = 0
    event_ids: list[str] = Field(default_factory=list)
    content_type: str = ""


def _extract_org_id(x_org_id: str | None) -> str:
    return x_org_id or "default"


@router.post("/logs", status_code=202, response_model=OTLPLogsResponse)
async def ingest_otlp_logs(
    request: Request,
    content_type: str | None = Header(default=None, alias="Content-Type"),
    x_org_id: str | None = Header(default=None, alias="X-Org-Id"),
) -> OTLPLogsResponse:
    """Ingest OTLP log records over HTTP.

    Supports:
        * ``application/json`` — OTLP/HTTP JSON ``ExportLogsServiceRequest``.
        * ``application/x-protobuf`` — OTLP/HTTP Protobuf
          ``ExportLogsServiceRequest``.
    """
    org_id = _extract_org_id(x_org_id)
    body_bytes = await request.body()
    if not body_bytes:
        raise HTTPException(status_code=400, detail="Empty OTLP payload")

    ctype = (content_type or "").split(";")[0].strip().lower()

    events: list[dict] = []
    if ctype in ("application/x-protobuf", "application/protobuf"):
        try:
            events = otlp_http_protobuf_to_events(body_bytes)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=415,
                detail=f"OTLP protobuf support unavailable: {exc}",
            ) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid OTLP protobuf payload: {exc}",
            ) from exc
    else:
        # Default to JSON for unknown / application/json content-types.
        import json as json_mod

        try:
            body = json_mod.loads(body_bytes.decode("utf-8", errors="replace"))
        except json_mod.JSONDecodeError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid OTLP JSON payload: {exc}",
            ) from exc
        if not isinstance(body, dict):
            raise HTTPException(
                status_code=400,
                detail="OTLP JSON payload must be a LogsData object",
            )
        events = otlp_http_json_to_events(body)

    if not events:
        raise HTTPException(
            status_code=400,
            detail="No OTLP log records found in payload",
        )

    batch = await process_batch(events, "otel", org_id)

    logger.info(
        "otlp.http_logs_ingested",
        org_id=org_id,
        accepted=batch.accepted,
        rejected=batch.rejected,
        content_type=ctype,
    )

    return OTLPLogsResponse(
        events_accepted=batch.accepted,
        events_rejected=batch.rejected,
        event_ids=batch.event_ids,
        content_type=ctype,
    )
