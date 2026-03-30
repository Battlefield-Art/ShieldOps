"""Incident Timeline Builder Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ITBStage(StrEnum):
    COLLECT_EVENTS = "collect_events"
    CORRELATE_SOURCES = "correlate_sources"
    BUILD_TIMELINE = "build_timeline"
    IDENTIFY_ROOT_CAUSE = "identify_root_cause"
    GENERATE_NARRATIVE = "generate_narrative"
    REPORT = "report"


class EventSource(StrEnum):
    SIEM = "siem"
    EDR = "edr"
    NETWORK = "network"
    CLOUD_TRAIL = "cloud_trail"
    IDENTITY = "identity"
    APPLICATION = "application"


class EventSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RawEvent(BaseModel):
    """A raw event from a single source."""

    id: str = ""
    source: EventSource = EventSource.SIEM
    timestamp: str = ""
    severity: EventSeverity = EventSeverity.INFO
    host: str = ""
    user: str = ""
    action: str = ""
    description: str = ""
    raw_log: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class CorrelatedEvent(BaseModel):
    """An event correlated across multiple sources."""

    id: str = ""
    event_ids: list[str] = Field(default_factory=list)
    sources: list[EventSource] = Field(default_factory=list)
    timestamp: str = ""
    severity: EventSeverity = EventSeverity.INFO
    host: str = ""
    user: str = ""
    action: str = ""
    description: str = ""
    correlation_score: float = 0.0


class TimelineEntry(BaseModel):
    """A single entry in the reconstructed timeline."""

    id: str = ""
    timestamp: str = ""
    severity: EventSeverity = EventSeverity.INFO
    title: str = ""
    description: str = ""
    sources: list[EventSource] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    correlated_event_id: str = ""


class RootCauseAnalysis(BaseModel):
    """Root cause analysis for the incident."""

    probable_cause: str = ""
    confidence: float = 0.0
    attack_vector: str = ""
    initial_access_time: str = ""
    initial_access_host: str = ""
    contributing_factors: list[str] = Field(
        default_factory=list,
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
    )


class IncidentNarrative(BaseModel):
    """A human-readable narrative of the incident."""

    executive_summary: str = ""
    detailed_narrative: str = ""
    impact_assessment: str = ""
    recommendations: list[str] = Field(
        default_factory=list,
    )


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentTimelineBuilderState(BaseModel):
    """Main state for the Incident Timeline Builder agent."""

    request_id: str = ""
    tenant_id: str = ""
    incident_id: str = ""
    stage: ITBStage = ITBStage.COLLECT_EVENTS

    raw_events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    correlated_events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    timeline_entries: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    root_cause: dict[str, Any] = Field(
        default_factory=dict,
    )
    narrative: dict[str, Any] = Field(
        default_factory=dict,
    )

    report: str = ""
    total_events: int = 0
    total_correlated: int = 0
    timeline_span_minutes: float = 0.0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
