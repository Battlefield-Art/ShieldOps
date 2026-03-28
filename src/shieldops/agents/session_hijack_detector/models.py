"""Session Hijack Detector Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DetectionStage(StrEnum):
    """Stages of the session hijack detection workflow."""

    COLLECT_SESSIONS = "collect_sessions"
    ANALYZE_ANOMALIES = "analyze_anomalies"
    CORRELATE_INDICATORS = "correlate_indicators"
    ASSESS_RISK = "assess_risk"
    RESPOND = "respond"
    REPORT = "report"


class HijackType(StrEnum):
    """Types of session hijacking attacks."""

    TOKEN_THEFT = "token_theft"  # noqa: S105
    COOKIE_MANIPULATION = "cookie_manipulation"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    SESSION_REPLAY = "session_replay"
    CONCURRENT_GEO = "concurrent_geo"
    SESSION_FIXATION = "session_fixation"
    SIDEJACKING = "sidejacking"


class SessionRisk(StrEnum):
    """Risk level for a detected session anomaly."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# --- Domain Models ---


class SessionEvent(BaseModel):
    """A raw session event from authentication telemetry."""

    event_id: str = ""
    session_id: str = ""
    user_id: str = ""
    ip_address: str = ""
    user_agent: str = ""
    geo_country: str = ""
    geo_city: str = ""
    geo_lat: float = 0.0
    geo_lon: float = 0.0
    action: str = ""
    token_hash: str = ""
    cookie_flags: dict[str, Any] = Field(default_factory=dict)
    timestamp: float = 0.0
    provider: str = ""


class HijackIndicator(BaseModel):
    """An indicator of a potential session hijacking attempt."""

    indicator_id: str = ""
    session_id: str = ""
    user_id: str = ""
    hijack_type: str = "token_theft"
    risk: str = "medium"
    confidence: float = 0.0
    source_ip: str = ""
    anomalous_ip: str = ""
    source_geo: str = ""
    anomalous_geo: str = ""
    travel_speed_kmh: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    mitre_technique: str = ""
    timestamp: float = 0.0


class ResponseAction(BaseModel):
    """An automated response action for a hijack detection."""

    action_id: str = ""
    action_type: str = ""
    target_session_id: str = ""
    target_user_id: str = ""
    reason: str = ""
    executed: bool = False
    requires_approval: bool = False
    result: str = ""
    execution_time_ms: int = 0


class HijackReport(BaseModel):
    """Final report for a session hijack detection run."""

    report_id: str = ""
    tenant_id: str = ""
    sessions_analyzed: int = 0
    indicators_found: int = 0
    hijacks_confirmed: int = 0
    responses_executed: int = 0
    hijack_types: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    risk_summary: dict[str, int] = Field(default_factory=dict)
    summary: str = ""


class ReasoningStep(BaseModel):
    """Audit trail entry for the detection workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SessionHijackDetectorState(BaseModel):
    """Full state for a session hijack detection run."""

    # Input
    tenant_id: str = ""
    detection_id: str = ""
    raw_events: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Collection
    sessions: list[SessionEvent] = Field(
        default_factory=list,
    )
    unique_users: int = 0

    # Analysis
    indicators: list[HijackIndicator] = Field(
        default_factory=list,
    )
    anomaly_count: int = 0

    # Correlation
    correlated_indicators: list[HijackIndicator] = Field(
        default_factory=list,
    )
    confirmed_hijacks: int = 0

    # Risk assessment
    overall_risk: str = "low"
    risk_score: float = 0.0
    auto_respond: bool = False

    # Response
    response_actions: list[ResponseAction] = Field(
        default_factory=list,
    )
    responses_executed: int = 0

    # Outcome
    report: HijackReport | None = None

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
