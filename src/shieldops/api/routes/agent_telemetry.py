"""Agent telemetry ingestion — accepts SDK events from the Agent Firewall SDK.

The ShieldOps Agent Firewall SDK (LangChain / CrewAI / LlamaIndex callbacks)
emits telemetry events back to the control plane: tool-call records, policy
decisions, and runtime metrics. This endpoint routes those events through the
standard ingestion pipeline (``process_event`` / ``process_batch``) with the
source provider tag ``shieldops_sdk`` so that they land in the same OCSF data
lake as every other security signal.

Endpoint
--------
* ``POST /api/v1/ingest/telemetry``  — accept one or many SDK telemetry events.
"""

from __future__ import annotations

from typing import Any, Literal

import structlog
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from shieldops.ingestion.pipeline import process_batch, process_event

logger = structlog.get_logger()

router = APIRouter(prefix="/ingest/telemetry", tags=["Agent Telemetry"])

_SOURCE_PROVIDER = "shieldops_sdk"


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class TelemetryEvent(BaseModel):
    """A single telemetry event emitted by the Agent Firewall SDK."""

    event_type: Literal["tool_call", "decision", "metric", "log"] = "tool_call"
    agent_id: str = ""
    agent_name: str = ""
    framework: str = ""  # "langchain" | "crewai" | "llamaindex" | ...
    tool_name: str = ""
    timestamp: str = ""  # ISO 8601
    severity: str = "info"
    decision: str = ""  # "allow" | "block" | "audit"
    inputs: dict[str, Any] = Field(default_factory=dict)
    outputs: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}


class TelemetryRequest(BaseModel):
    """Batch wrapper for telemetry ingestion."""

    events: list[TelemetryEvent] = Field(default_factory=list)
    model_config = {"extra": "forbid"}


class TelemetryResponse(BaseModel):
    """Response for telemetry ingestion."""

    status: str = "accepted"
    source: str = _SOURCE_PROVIDER
    events_accepted: int = 0
    events_rejected: int = 0
    event_ids: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_org_id(x_org_id: str | None) -> str:
    return x_org_id or "default"


def _event_to_raw(event: TelemetryEvent) -> dict[str, Any]:
    """Convert a TelemetryEvent to a raw dict for the pipeline."""
    return event.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.post("", status_code=202, response_model=TelemetryResponse)
async def ingest_agent_telemetry(
    payload: TelemetryRequest | TelemetryEvent,
    x_org_id: str | None = Header(default=None, alias="X-Org-Id"),
) -> TelemetryResponse:
    """Ingest SDK telemetry events (tool calls, decisions, metrics).

    Accepts either a single ``TelemetryEvent`` object or a ``TelemetryRequest``
    batch. All events are tagged with ``source_provider="shieldops_sdk"`` and
    routed through the standard ingestion pipeline.
    """
    org_id = _extract_org_id(x_org_id)

    if isinstance(payload, TelemetryEvent):
        events = [payload]
    else:
        events = list(payload.events)

    if not events:
        raise HTTPException(status_code=400, detail="No telemetry events in payload")

    # Single-event fast path uses process_event for parity with webhook routes.
    if len(events) == 1:
        try:
            event_id = await process_event(
                _event_to_raw(events[0]),
                source_provider=_SOURCE_PROVIDER,
                org_id=org_id,
            )
        except Exception as exc:
            logger.exception("agent_telemetry.single_failed", org_id=org_id)
            return TelemetryResponse(
                status="rejected",
                events_accepted=0,
                events_rejected=1,
                errors=[str(exc)],
            )

        logger.info(
            "agent_telemetry.ingested",
            org_id=org_id,
            event_id=event_id,
            event_type=events[0].event_type,
        )
        return TelemetryResponse(
            events_accepted=1,
            events_rejected=0,
            event_ids=[event_id],
        )

    raw_events = [_event_to_raw(e) for e in events]
    batch = await process_batch(raw_events, _SOURCE_PROVIDER, org_id)

    logger.info(
        "agent_telemetry.batch_ingested",
        org_id=org_id,
        accepted=batch.accepted,
        rejected=batch.rejected,
    )

    return TelemetryResponse(
        events_accepted=batch.accepted,
        events_rejected=batch.rejected,
        event_ids=batch.event_ids,
        errors=batch.errors,
    )
