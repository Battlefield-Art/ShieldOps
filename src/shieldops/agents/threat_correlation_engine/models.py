"""Threat Correlation Engine Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CorrelationStage(StrEnum):
    COLLECT_EVENTS = "collect_events"
    NORMALIZE_DATA = "normalize_data"
    CORRELATE_SIGNALS = "correlate_signals"
    SCORE_THREATS = "score_threats"
    GENERATE_ALERTS = "generate_alerts"
    REPORT = "report"


class ThreatCategory(StrEnum):
    MALWARE = "malware"
    PHISHING = "phishing"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    COMMAND_AND_CONTROL = "command_and_control"


class CorrelationConfidence(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ThreatCorrelationEngineState(BaseModel):
    request_id: str = ""
    stage: CorrelationStage = CorrelationStage.COLLECT_EVENTS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
