"""Incident Prediction Engine Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PredictionStage(StrEnum):
    COLLECT_SIGNALS = "collect_signals"
    EXTRACT_FEATURES = "extract_features"
    RUN_MODELS = "run_models"
    RANK_PREDICTIONS = "rank_predictions"
    ALERT = "alert"
    REPORT = "report"


class PredictionType(StrEnum):
    RANSOMWARE = "ransomware"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    DDOS = "ddos"
    SUPPLY_CHAIN = "supply_chain"
    ACCOUNT_COMPROMISE = "account_compromise"


class ConfidenceLevel(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCERTAIN = "uncertain"


class IncidentPredictionEngineState(BaseModel):
    request_id: str = ""
    stage: PredictionStage = PredictionStage.COLLECT_SIGNALS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
