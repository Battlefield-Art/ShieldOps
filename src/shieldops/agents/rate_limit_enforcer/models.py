"""Rate Limit Enforcer Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RLEStage(StrEnum):
    MONITOR_TRAFFIC = "monitor_traffic"
    DETECT_ANOMALIES = "detect_anomalies"
    CLASSIFY_PATTERNS = "classify_patterns"
    APPLY_LIMITS = "apply_limits"
    NOTIFY_STAKEHOLDERS = "notify_stakeholders"
    REPORT = "report"


class TrafficPattern(StrEnum):
    BURST = "burst"
    SUSTAINED = "sustained"
    GRADUAL = "gradual"
    CYCLIC = "cyclic"
    RANDOM = "random"
    TARGETED = "targeted"


class LimitAction(StrEnum):
    BLOCK = "block"
    THROTTLE = "throttle"
    CHALLENGE = "challenge"
    WARN = "warn"
    ALLOW = "allow"
    WHITELIST = "whitelist"


class RateLimitEnforcerState(BaseModel):
    request_id: str = ""
    stage: RLEStage = RLEStage.MONITOR_TRAFFIC
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
