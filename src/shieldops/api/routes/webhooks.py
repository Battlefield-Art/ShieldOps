"""Webhook receiver endpoints — CloudTrail, CrowdStrike, GuardDuty.

Each endpoint accepts vendor-native webhook payloads, extracts events,
and pushes them through the ingestion pipeline (OCSF normalize + DuckDB store).

All endpoints return 202 Accepted with a summary of processed events.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from shieldops.ingestion.pipeline import process_batch

logger = structlog.get_logger()

router = APIRouter(prefix="/ingest/webhook", tags=["Webhooks"])


# ---------------------------------------------------------------------------
# Response model
# ---------------------------------------------------------------------------


class WebhookResponse(BaseModel):
    """Standard response for webhook ingestion endpoints."""

    status: str = "accepted"
    source: str = ""
    events_accepted: int = 0
    events_rejected: int = 0
    event_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_org_id(
    x_org_id: str | None = None,
) -> str:
    """Extract org_id from header, falling back to 'default'."""
    return x_org_id or "default"


# ---------------------------------------------------------------------------
# CloudTrail webhook
# ---------------------------------------------------------------------------


@router.post("/cloudtrail", status_code=202, response_model=WebhookResponse)
async def ingest_cloudtrail(
    request: Request,
    x_org_id: str | None = Header(default=None, alias="X-Org-Id"),
) -> WebhookResponse:
    """Ingest AWS CloudTrail events via SNS notification or direct POST.

    Accepts:
    - SNS notification wrapper (``{"Records": [...]}`` or ``{"Message": "..."}``).
    - Direct CloudTrail event (single dict).
    - Array of CloudTrail events.
    """
    org_id = _extract_org_id(x_org_id)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from None

    events = _extract_cloudtrail_events(body)

    if not events:
        raise HTTPException(
            status_code=400,
            detail="No CloudTrail events found in payload",
        )

    batch = await process_batch(events, "cloudtrail", org_id)

    logger.info(
        "webhook.cloudtrail",
        org_id=org_id,
        accepted=batch.accepted,
        rejected=batch.rejected,
    )

    return WebhookResponse(
        source="cloudtrail",
        events_accepted=batch.accepted,
        events_rejected=batch.rejected,
        event_ids=batch.event_ids,
    )


def _extract_cloudtrail_events(body: Any) -> list[dict[str, Any]]:
    """Extract CloudTrail events from various SNS/direct payload formats."""
    import json as json_mod

    if isinstance(body, list):
        return [e for e in body if isinstance(e, dict)]

    if not isinstance(body, dict):
        return []

    # SNS notification with JSON-encoded Message containing Records
    if "Message" in body:
        try:
            message = body["Message"]
            if isinstance(message, str):
                message = json_mod.loads(message)
            if isinstance(message, dict) and "Records" in message:
                return [r for r in message["Records"] if isinstance(r, dict)]
            if isinstance(message, dict):
                return [message]
            if isinstance(message, list):
                return [e for e in message if isinstance(e, dict)]
        except (json_mod.JSONDecodeError, TypeError):
            pass

    # Direct CloudTrail Records array
    if "Records" in body:
        records = body["Records"]
        if isinstance(records, list):
            return [r for r in records if isinstance(r, dict)]

    # Single CloudTrail event (has eventName or eventSource)
    if "eventName" in body or "eventSource" in body:
        return [body]

    return []


# ---------------------------------------------------------------------------
# CrowdStrike webhook
# ---------------------------------------------------------------------------


@router.post("/crowdstrike", status_code=202, response_model=WebhookResponse)
async def ingest_crowdstrike(
    request: Request,
    x_org_id: str | None = Header(default=None, alias="X-Org-Id"),
) -> WebhookResponse:
    """Ingest CrowdStrike FDR / detection events.

    Accepts:
    - Single detection event (dict with detection_id or detect_name).
    - Array of detection events.
    - CrowdStrike FDR batch wrapper (``{"resources": [...]}``, ``{"events": [...]}``,
      or ``{"detections": [...]}``)
    """
    org_id = _extract_org_id(x_org_id)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from None

    events = _extract_crowdstrike_events(body)

    if not events:
        raise HTTPException(
            status_code=400,
            detail="No CrowdStrike events found in payload",
        )

    batch = await process_batch(events, "crowdstrike", org_id)

    logger.info(
        "webhook.crowdstrike",
        org_id=org_id,
        accepted=batch.accepted,
        rejected=batch.rejected,
    )

    return WebhookResponse(
        source="crowdstrike",
        events_accepted=batch.accepted,
        events_rejected=batch.rejected,
        event_ids=batch.event_ids,
    )


def _extract_crowdstrike_events(body: Any) -> list[dict[str, Any]]:
    """Extract CrowdStrike events from FDR/direct payload formats."""
    if isinstance(body, list):
        return [e for e in body if isinstance(e, dict)]

    if not isinstance(body, dict):
        return []

    # FDR batch wrappers
    for key in ("resources", "events", "detections"):
        if key in body:
            items = body[key]
            if isinstance(items, list):
                return [e for e in items if isinstance(e, dict)]

    # Single detection event
    if "detection_id" in body or "detect_name" in body or "composite_id" in body:
        return [body]

    return []


# ---------------------------------------------------------------------------
# GuardDuty webhook
# ---------------------------------------------------------------------------


@router.post("/guardduty", status_code=202, response_model=WebhookResponse)
async def ingest_guardduty(
    request: Request,
    x_org_id: str | None = Header(default=None, alias="X-Org-Id"),
) -> WebhookResponse:
    """Ingest AWS GuardDuty findings via EventBridge or SNS.

    Accepts:
    - EventBridge event (``{"detail": {...}, "detail-type": "GuardDuty Finding"}``).
    - SNS notification wrapping a GuardDuty finding.
    - Direct GuardDuty finding dict.
    - Array of findings.
    """
    org_id = _extract_org_id(x_org_id)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from None

    events = _extract_guardduty_events(body)

    if not events:
        raise HTTPException(
            status_code=400,
            detail="No GuardDuty findings found in payload",
        )

    batch = await process_batch(events, "guardduty", org_id)

    logger.info(
        "webhook.guardduty",
        org_id=org_id,
        accepted=batch.accepted,
        rejected=batch.rejected,
    )

    return WebhookResponse(
        source="guardduty",
        events_accepted=batch.accepted,
        events_rejected=batch.rejected,
        event_ids=batch.event_ids,
    )


def _extract_guardduty_events(body: Any) -> list[dict[str, Any]]:
    """Extract GuardDuty findings from EventBridge/SNS/direct formats."""
    import json as json_mod

    if isinstance(body, list):
        return [e for e in body if isinstance(e, dict)]

    if not isinstance(body, dict):
        return []

    # EventBridge format: {"detail-type": "GuardDuty Finding", "detail": {...}}
    if "detail" in body and isinstance(body.get("detail"), dict):
        return [body["detail"]]

    # SNS notification with JSON-encoded Message
    if "Message" in body:
        try:
            message = body["Message"]
            if isinstance(message, str):
                message = json_mod.loads(message)
            if isinstance(message, dict):
                return [message]
            if isinstance(message, list):
                return [e for e in message if isinstance(e, dict)]
        except (json_mod.JSONDecodeError, TypeError):
            pass

    # Direct GuardDuty finding (has Id/Title/Severity or Type containing ":")
    if any(k in body for k in ("Id", "Title", "Severity", "Type")):
        return [body]

    # findings wrapper
    if "findings" in body and isinstance(body["findings"], list):
        return [f for f in body["findings"] if isinstance(f, dict)]

    return []
