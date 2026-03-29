"""Federated Learning Security Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class FLStage(StrEnum):
    INSPECT_GRADIENTS = "inspect_gradients"
    DETECT_POISONING = "detect_poisoning"
    SCORE_PARTICIPANTS = "score_participants"
    VERIFY_AGGREGATION = "verify_aggregation"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class ThreatType(StrEnum):
    GRADIENT_POISONING = "gradient_poisoning"
    MODEL_POISONING = "model_poisoning"
    FREE_RIDING = "free_riding"
    INFERENCE_ATTACK = "inference_attack"
    BACKDOOR = "backdoor"
    DATA_LEAKAGE = "data_leakage"


class ParticipantStatus(StrEnum):
    TRUSTED = "trusted"
    SUSPICIOUS = "suspicious"
    BLOCKED = "blocked"
    NEW = "new"
    UNDER_REVIEW = "under_review"


class GradientCheck(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class ParticipantScore(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class AggregationResult(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class FederatedLearningSecurityState(BaseModel):
    request_id: str = ""
    stage: FLStage = FLStage.INSPECT_GRADIENTS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
