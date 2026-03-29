"""Physical Access Monitor Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MonitorStage(StrEnum):
    INGEST_EVENTS = "ingest_events"
    ANALYZE_PATTERNS = "analyze_patterns"
    DETECT_ANOMALIES = "detect_anomalies"
    EVALUATE_POLICIES = "evaluate_policies"
    GENERATE_ALERTS = "generate_alerts"
    REPORT = "report"


class AccessType(StrEnum):
    BADGE_SWIPE = "badge_swipe"
    BIOMETRIC = "biometric"
    PIN_CODE = "pin_code"
    TAILGATE = "tailgate"
    FORCED_ENTRY = "forced_entry"
    VISITOR_PASS = "visitor_pass"  # noqa: S105


class AlertLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AccessEvent(BaseModel):
    """A physical access event from badge readers or sensors."""

    event_id: str = ""
    person_id: str = ""
    person_name: str = ""
    badge_id: str = ""
    access_type: AccessType = AccessType.BADGE_SWIPE
    zone: str = ""
    door_id: str = ""
    timestamp: float = 0.0
    granted: bool = True
    after_hours: bool = False
    restricted_area: bool = False


class ZonePolicy(BaseModel):
    """Access policy for a physical zone."""

    zone_id: str = ""
    zone_name: str = ""
    max_occupancy: int = 0
    requires_escort: bool = False
    restricted_hours_start: str = ""
    restricted_hours_end: str = ""
    allowed_roles: list[str] = Field(default_factory=list)
    mfa_required: bool = False


class PhysicalAccessMonitorState(BaseModel):
    """Full graph state for the Physical Access Monitor agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: MonitorStage = MonitorStage.INGEST_EVENTS
    current_step: str = ""
    time_range_hours: int = 24
    zones: list[str] = Field(default_factory=list)
    access_events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    patterns_detected: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    anomalies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    policy_violations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    alerts_generated: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
