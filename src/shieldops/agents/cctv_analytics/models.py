"""CCTV Analytics Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AnalyticsStage(StrEnum):
    COLLECT_FEEDS = "collect_feeds"
    DETECT_MOTION = "detect_motion"
    ANALYZE_BEHAVIOR = "analyze_behavior"
    CLASSIFY_EVENTS = "classify_events"
    ALERT = "alert"
    REPORT = "report"


class DetectionType(StrEnum):
    MOTION = "motion"
    PERSON = "person"
    VEHICLE = "vehicle"
    PERIMETER_BREACH = "perimeter_breach"
    LOITERING = "loitering"
    CROWD = "crowd"


class CameraStatus(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    TAMPERED = "tampered"
    MAINTENANCE = "maintenance"


class VideoEvent(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class AnalyticsResult(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class CameraHealth(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class CCTVAnalyticsState(BaseModel):
    request_id: str = ""
    stage: AnalyticsStage = AnalyticsStage.COLLECT_FEEDS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
