"""Adaptive Security Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AdaptationStage(StrEnum):
    BASELINE = "baseline"
    DETECT_DRIFT = "detect_drift"
    PROPOSE_ADJUSTMENT = "propose_adjustment"
    EVALUATE = "evaluate"
    APPLY = "apply"


class ThreatContext(StrEnum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    ACTIVE_ATTACK = "active_attack"
    POST_INCIDENT = "post_incident"


class ThresholdType(StrEnum):
    RISK_SCORE = "risk_score"
    ALERT_VOLUME = "alert_volume"
    ANOMALY_SENSITIVITY = "anomaly_sensitivity"
    RESPONSE_URGENCY = "response_urgency"


class BaselineMetrics(BaseModel):
    """Baseline measurement for a specific metric."""

    entity_type: str = ""
    metric_name: str = ""
    current_value: float = 0.0
    baseline_value: float = 0.0
    drift_pct: float = 0.0
    window_hours: int = 24


class ThresholdProposal(BaseModel):
    """A proposed threshold adjustment."""

    threshold_type: ThresholdType = ThresholdType.RISK_SCORE
    current_value: float = 0.0
    proposed_value: float = 0.0
    reasoning: str = ""
    confidence: float = 0.0
    risk: str = "low"


class AdaptationResult(BaseModel):
    """Result of evaluating a threshold proposal."""

    proposal_id: str = ""
    accepted: bool = False
    actual_impact: str = ""
    false_positive_delta: float = 0.0
    detection_delta: float = 0.0


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AdaptiveSecurityState(BaseModel):
    """Main state for the Adaptive Security agent graph."""

    request_id: str = ""
    stage: AdaptationStage = AdaptationStage.BASELINE
    threat_context: ThreatContext = ThreatContext.NORMAL
    window_hours: int = 24

    # Baselines
    baselines: list[BaselineMetrics] = Field(default_factory=list)

    # Proposals
    proposals: list[ThresholdProposal] = Field(default_factory=list)

    # Evaluation results
    results: list[AdaptationResult] = Field(default_factory=list)

    # Counters
    accepted_count: int = 0
    confidence_score: float = 0.0

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
