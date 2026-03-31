"""State models for the Security Event Enricher Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class SEEStage(StrEnum):
    """Stages in the security event enrichment lifecycle."""

    RECEIVE_EVENTS = "receive_events"
    LOOKUP_CONTEXT = "lookup_context"
    ENRICH_THREAT = "enrich_threat"
    SCORE_PRIORITY = "score_priority"
    ROUTE = "route"
    REPORT = "report"


class EventSource(StrEnum):
    """Source of security events."""

    SIEM = "siem"
    EDR = "edr"
    CLOUD_TRAIL = "cloud_trail"
    FIREWALL = "firewall"
    IDS_IPS = "ids_ips"
    APPLICATION = "application"


class PriorityLevel(StrEnum):
    """Priority level for enriched events."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    SUPPRESSED = "suppressed"


# --- Domain models ---


class SecurityEvent(BaseModel):
    """A raw security event received for enrichment."""

    event_id: str = ""
    source: EventSource = EventSource.SIEM
    event_type: str = ""
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime | None = None
    source_ip: str = ""
    dest_ip: str = ""


class ContextLookup(BaseModel):
    """Context information looked up for an event."""

    event_id: str = ""
    asset_info: dict[str, Any] = Field(default_factory=dict)
    user_info: dict[str, Any] = Field(default_factory=dict)
    geo_info: dict[str, Any] = Field(default_factory=dict)
    historical_alerts: int = 0


class ThreatEnrichment(BaseModel):
    """Threat intelligence enrichment for an event."""

    event_id: str = ""
    ioc_matches: list[str] = Field(default_factory=list)
    threat_actor: str = ""
    campaign: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class ScoredEvent(BaseModel):
    """A priority-scored enriched event."""

    event_id: str = ""
    priority: PriorityLevel = PriorityLevel.LOW
    score: float = 0.0
    factors: list[str] = Field(default_factory=list)
    auto_actionable: bool = False


class RoutingDecision(BaseModel):
    """Routing decision for an enriched event."""

    event_id: str = ""
    destination: str = ""
    priority: PriorityLevel = PriorityLevel.LOW
    sla_minutes: int = 60
    assigned_team: str = ""


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the enricher workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityEventEnricherState(BaseModel):
    """Full state for a security event enricher run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: SEEStage = SEEStage.RECEIVE_EVENTS

    # Inputs
    event_sources: list[EventSource] = Field(
        default_factory=list,
    )
    scope: dict[str, Any] = Field(default_factory=dict)
    batch_size: int = 100

    # Pipeline fields
    events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    context_lookups: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    enrichments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    scored_events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    routing_decisions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_events: int = 0
    enriched_count: int = 0
    critical_count: int = 0
    routed_count: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
