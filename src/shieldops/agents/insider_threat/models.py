"""Insider Threat Detection Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class InsiderStage(StrEnum):
    COLLECT_USER_SIGNALS = "collect_user_signals"
    BUILD_BEHAVIORAL_BASELINE = "build_behavioral_baseline"
    DETECT_DEVIATIONS = "detect_deviations"
    ASSESS_RISK = "assess_risk"
    INVESTIGATE = "investigate"
    REPORT = "report"


class ThreatIndicator(StrEnum):
    DATA_HOARDING = "data_hoarding"
    OFF_HOURS_ACCESS = "off_hours_access"
    PRIVILEGE_ABUSE = "privilege_abuse"
    RESIGNATION_RISK = "resignation_risk"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"
    BULK_DOWNLOAD = "bulk_download"


class RiskCategory(StrEnum):
    FLIGHT_RISK = "flight_risk"
    DATA_THEFT = "data_theft"
    SABOTAGE = "sabotage"
    ESPIONAGE = "espionage"
    NEGLIGENCE = "negligence"


class UserSignal(BaseModel):
    """A single identity/behavioral signal from any data source."""

    id: str = ""
    user_id: str = ""
    user_email: str = ""
    source: str = ""
    signal_type: str = ""
    action: str = ""
    resource: str = ""
    timestamp: float = 0.0
    geo_location: str = ""
    device_id: str = ""
    risk_indicators: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BehavioralBaseline(BaseModel):
    """Normal behavioral profile for a user over a baseline period."""

    user_id: str = ""
    baseline_period_days: int = 30
    avg_daily_logins: float = 0.0
    typical_hours_start: int = 8
    typical_hours_end: int = 18
    typical_geos: list[str] = Field(default_factory=list)
    typical_resources: list[str] = Field(default_factory=list)
    avg_daily_data_volume_mb: float = 0.0
    typical_tools: list[str] = Field(default_factory=list)
    privilege_level: str = "standard"
    department: str = ""
    last_updated: float = 0.0


class BehaviorDeviation(BaseModel):
    """A detected deviation from the user behavioral baseline."""

    id: str = ""
    user_id: str = ""
    indicator: ThreatIndicator = ThreatIndicator.OFF_HOURS_ACCESS
    description: str = ""
    severity: float = 0.0
    baseline_value: str = ""
    observed_value: str = ""
    timestamp: float = 0.0
    confidence: float = 0.0
    mitre_technique: str = ""


class InsiderRiskScore(BaseModel):
    """Composite risk score for a user across all indicators."""

    user_id: str = ""
    overall_score: float = 0.0
    category: RiskCategory = RiskCategory.NEGLIGENCE
    indicator_scores: dict[str, float] = Field(default_factory=dict)
    deviation_count: int = 0
    high_severity_count: int = 0
    recommended_actions: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class InsiderInvestigation(BaseModel):
    """An investigation opened for a high-risk insider threat."""

    id: str = ""
    user_id: str = ""
    risk_score: float = 0.0
    category: RiskCategory = RiskCategory.NEGLIGENCE
    deviations: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    status: str = "open"
    assigned_to: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class InsiderThreatState(BaseModel):
    """Main state for the Insider Threat Detection graph."""

    # Input
    request_id: str = ""
    stage: InsiderStage = InsiderStage.COLLECT_USER_SIGNALS
    tenant_id: str = ""
    time_window_hours: int = 24

    # Detection pipeline
    users_monitored: list[str] = Field(default_factory=list)
    user_signals: list[dict[str, Any]] = Field(default_factory=list)
    baselines_built: list[dict[str, Any]] = Field(default_factory=list)
    deviations_detected: list[dict[str, Any]] = Field(default_factory=list)
    risk_scores: list[dict[str, Any]] = Field(default_factory=list)
    investigations: list[dict[str, Any]] = Field(default_factory=list)
    high_risk_users: list[str] = Field(default_factory=list)

    # Stats & workflow
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
