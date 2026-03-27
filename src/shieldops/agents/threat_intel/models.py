"""State models for the Threat Intel Agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IntelStage(StrEnum):
    """Stages of the threat intelligence lifecycle."""

    COLLECT = "collect"
    CORRELATE = "correlate"
    ASSESS = "assess"
    DISTRIBUTE = "distribute"


class IntelSource(StrEnum):
    """Sources of threat intelligence."""

    OSINT = "osint"
    COMMERCIAL = "commercial"
    ISAC = "isac"
    INTERNAL = "internal"
    DARK_WEB = "dark_web"


class ThreatConfidence(StrEnum):
    """Confidence levels for threat indicators."""

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    UNVERIFIED = "unverified"


class IndicatorType(StrEnum):
    """Types of threat indicators (IOCs)."""

    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"
    CVE = "cve"


class ThreatIndicator(BaseModel):
    """A single threat indicator collected from an intelligence feed."""

    value: str
    indicator_type: IndicatorType
    source: IntelSource
    confidence: ThreatConfidence = ThreatConfidence.UNVERIFIED
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)


class IntelCorrelation(BaseModel):
    """Result of correlating an indicator against internal observations."""

    indicator_value: str
    internal_matches: list[dict[str, Any]] = Field(default_factory=list)
    match_count: int = 0
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    entities_affected: list[str] = Field(default_factory=list)


class ThreatAssessment(BaseModel):
    """Assessment of how relevant and actionable a threat indicator is."""

    indicator_value: str
    relevance_score: float = Field(default=0.0, ge=0.0, le=1.0)
    actionable: bool = False
    recommended_actions: list[str] = Field(default_factory=list)
    ttl_hours: int = 24


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ThreatIntelState(BaseModel):
    """Full state of a threat intelligence workflow (LangGraph state)."""

    # Input
    request_id: str = ""
    stage: IntelStage = IntelStage.COLLECT
    sources: list[IntelSource] = Field(default_factory=list)

    # Collected indicators
    indicators_collected: list[ThreatIndicator] = Field(default_factory=list)

    # Correlation results
    correlations: list[IntelCorrelation] = Field(default_factory=list)

    # Assessments
    assessments: list[ThreatAssessment] = Field(default_factory=list)

    # Summary metrics
    high_priority_count: int = 0
    confidence_score: float = 0.0

    # Distribution
    distribution_channels: list[str] = Field(default_factory=list)
    distribution_results: dict[str, Any] = Field(default_factory=dict)

    # Metadata
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
