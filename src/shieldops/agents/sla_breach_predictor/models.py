"""SLA Breach Predictor Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PredictionStage(StrEnum):
    COLLECT_TICKETS = "collect_tickets"
    COMPUTE_VELOCITY = "compute_velocity"
    PREDICT_BREACH = "predict_breach"
    RANK_RISK = "rank_risk"
    ALERT = "alert"
    REPORT = "report"


class SLAMetric(StrEnum):
    RESPONSE_TIME = "response_time"
    RESOLUTION_TIME = "resolution_time"
    ESCALATION_TIME = "escalation_time"
    ACK_TIME = "ack_time"
    UPDATE_FREQUENCY = "update_frequency"


class BreachRisk(StrEnum):
    IMMINENT = "imminent"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    SAFE = "safe"


class SlaBreachPredictorState(BaseModel):
    request_id: str = ""
    stage: PredictionStage = PredictionStage.COLLECT_TICKETS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
