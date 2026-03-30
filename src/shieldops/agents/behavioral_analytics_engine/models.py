"""Behavioral Analytics Engine Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class BAEStage(StrEnum):
    COLLECT_TELEMETRY = "collect_telemetry"
    BUILD_PROFILES = "build_profiles"
    DETECT_ANOMALIES = "detect_anomalies"
    SCORE_RISK = "score_risk"
    ALERT_VIOLATIONS = "alert_violations"
    REPORT = "report"


class BehaviorType(StrEnum):
    LOGIN = "login"
    DATA_ACCESS = "data_access"
    PRIVILEGE_USE = "privilege_use"
    NETWORK = "network"
    APPLICATION = "application"
    PHYSICAL = "physical"


class AnomalyScore(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    BASELINE = "baseline"


class BehavioralAnalyticsEngineState(BaseModel):
    request_id: str = ""
    stage: BAEStage = BAEStage.COLLECT_TELEMETRY
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
