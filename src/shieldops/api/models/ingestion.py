"""Pydantic models for the ingestion API."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class IngestEvent(BaseModel):
    """A single telemetry event submitted for ingestion.

    ``raw_event`` intentionally accepts any JSON structure so that new
    fields from upstream providers are never rejected (schema evolution).
    """

    event_id: UUID = Field(default_factory=uuid4)
    source_provider: str = Field(
        ...,
        min_length=1,
        description="Origin system — aws, crowdstrike, splunk, etc.",
    )
    event_type: str = Field(
        ...,
        min_length=1,
        description="Category such as authentication, network, security_finding.",
    )
    timestamp: datetime
    severity: str | None = Field(
        default=None,
        description="Optional severity level (info, low, medium, high, critical).",
    )
    raw_event: dict[str, Any] = Field(
        ...,
        description="Original event payload — arbitrary JSON accepted.",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}


class IngestResponse(BaseModel):
    """Acknowledgement for a single ingested event."""

    event_id: UUID
    status: str = Field(description="accepted or rejected")
    message: str | None = None


class IngestBatchResponse(BaseModel):
    """Summary response for a batch ingestion request."""

    accepted: int = 0
    rejected: int = 0
    events: list[IngestResponse] = Field(default_factory=list)
