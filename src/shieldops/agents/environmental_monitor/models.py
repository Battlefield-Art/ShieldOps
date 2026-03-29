"""Environmental Monitor Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MonitorStage(StrEnum):
    COLLECT_READINGS = "collect_readings"
    CHECK_THRESHOLDS = "check_thresholds"
    CORRELATE_EVENTS = "correlate_events"
    ASSESS_RISK = "assess_risk"
    ALERT = "alert"
    REPORT = "report"


class SensorType(StrEnum):
    TEMPERATURE = "temperature"
    HUMIDITY = "humidity"
    POWER = "power"
    WATER_LEAK = "water_leak"
    AIR_QUALITY = "air_quality"
    SMOKE = "smoke"


class ThresholdStatus(StrEnum):
    NORMAL = "normal"
    WARNING = "warning"
    CRITICAL = "critical"
    OFFLINE = "offline"
    CALIBRATING = "calibrating"


class SensorReading(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class AlertCondition(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class ZoneStatus(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class EnvironmentalMonitorState(BaseModel):
    request_id: str = ""
    stage: MonitorStage = MonitorStage.COLLECT_READINGS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
