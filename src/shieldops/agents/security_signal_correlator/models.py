"""Security Signal Correlator Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SSCStage(StrEnum):
    COLLECT_SIGNALS = "collect_signals"
    NORMALIZE = "normalize"
    CORRELATE = "correlate"
    SCORE_CONFIDENCE = "score_confidence"
    GENERATE_INCIDENTS = "generate_incidents"
    REPORT = "report"


class SignalSource(StrEnum):
    EDR = "edr"
    SIEM = "siem"
    CLOUD = "cloud"
    NETWORK = "network"
    IDENTITY = "identity"
    APPLICATION = "application"


class CorrelationStrength(StrEnum):
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    TENTATIVE = "tentative"
    NONE = "none"


class SecuritySignal(BaseModel):
    """A raw security signal from any source."""

    id: str = ""
    source: SignalSource = SignalSource.SIEM
    timestamp: str = ""
    event_type: str = ""
    severity: str = "medium"
    entity: str = ""
    description: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)


class NormalizedSignal(BaseModel):
    """A signal normalized to common schema."""

    id: str = ""
    original_id: str = ""
    source: SignalSource = SignalSource.SIEM
    timestamp: str = ""
    event_type: str = ""
    severity: str = "medium"
    entity: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    confidence: float = 0.0


class Correlation(BaseModel):
    """A correlation between two or more signals."""

    id: str = ""
    signal_ids: list[str] = Field(default_factory=list)
    strength: CorrelationStrength = CorrelationStrength.TENTATIVE
    pattern: str = ""
    entity: str = ""
    time_window_minutes: int = 0
    shared_indicators: list[str] = Field(default_factory=list)


class ConfidenceScore(BaseModel):
    """Confidence scoring for a correlation."""

    id: str = ""
    correlation_id: str = ""
    score: float = 0.0
    factors: list[str] = Field(default_factory=list)
    noise_probability: float = 0.0
    is_actionable: bool = False


class GeneratedIncident(BaseModel):
    """An incident generated from correlated signals."""

    id: str = ""
    correlation_id: str = ""
    title: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    signal_count: int = 0
    entities: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecuritySignalCorrelatorState(BaseModel):
    """Main state for the Security Signal Correlator agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SSCStage = SSCStage.COLLECT_SIGNALS

    signals: list[SecuritySignal] = Field(default_factory=list)
    normalized: list[NormalizedSignal] = Field(default_factory=list)
    correlations: list[Correlation] = Field(default_factory=list)
    scores: list[ConfidenceScore] = Field(default_factory=list)
    incidents: list[GeneratedIncident] = Field(default_factory=list)

    report: str = ""
    total_signals_collected: int = 0
    incidents_generated: int = 0

    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str = ""
