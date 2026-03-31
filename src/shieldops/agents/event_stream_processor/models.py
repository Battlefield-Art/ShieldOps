"""Event Stream Processor Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ESPStage(StrEnum):
    CONNECT_STREAMS = "connect_streams"
    PARSE_EVENTS = "parse_events"
    ENRICH = "enrich"
    CORRELATE = "correlate"
    ROUTE = "route"
    REPORT = "report"


class EventFormat(StrEnum):
    CEF = "cef"
    LEEF = "leef"
    JSON = "json"
    SYSLOG = "syslog"
    OCSF = "ocsf"
    RAW = "raw"


class CorrelationSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class StreamConnection(BaseModel):
    """An active Kafka / event-stream connection."""

    id: str = ""
    topic: str = ""
    broker: str = ""
    partition: int = 0
    offset: int = 0
    consumer_group: str = ""
    format: EventFormat = EventFormat.JSON
    connected: bool = False
    lag: int = 0


class ParsedEvent(BaseModel):
    """A security event parsed from the stream."""

    id: str = ""
    stream_id: str = ""
    timestamp: str = ""
    format: EventFormat = EventFormat.JSON
    severity: str = "medium"
    source_ip: str = ""
    destination_ip: str = ""
    event_type: str = ""
    raw_message: str = ""
    fields: dict[str, Any] = Field(default_factory=dict)


class EnrichedEvent(BaseModel):
    """A parsed event enriched with threat-intel context."""

    id: str = ""
    event_id: str = ""
    hostname: str = ""
    geo_country: str = ""
    asn: str = ""
    threat_intel_match: bool = False
    ioc_type: str = ""
    ioc_value: str = ""
    risk_score: float = 0.0
    tags: list[str] = Field(default_factory=list)


class CorrelationRule(BaseModel):
    """A correlation rule that fired across enriched events."""

    id: str = ""
    rule_name: str = ""
    description: str = ""
    matched_event_ids: list[str] = Field(default_factory=list)
    severity: CorrelationSeverity = CorrelationSeverity.MEDIUM
    confidence: float = 0.0
    mitre_technique: str = ""
    fired_at: str = ""


class RouteDecision(BaseModel):
    """Routing decision for a correlated alert."""

    id: str = ""
    correlation_id: str = ""
    destination: str = ""
    priority: int = 1
    playbook: str = ""
    siem_forwarded: bool = False
    soar_triggered: bool = False
    ticket_created: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class EventStreamProcessorState(BaseModel):
    """Main state for the Event Stream Processor agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: ESPStage = ESPStage.CONNECT_STREAMS

    stream_connections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    parsed_events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    enriched_events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    correlations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    route_decisions: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    report: str = ""
    total_events_processed: int = 0
    correlations_fired: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
