"""State models for the Threat Intelligence Platform Agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IntelStage(StrEnum):
    """Stages of the intelligence lifecycle."""

    COLLECT = "collect_intelligence"
    NORMALIZE = "normalize_indicators"
    CORRELATE = "correlate_threats"
    ASSESS = "assess_relevance"
    ADVISE = "generate_advisories"
    REPORT = "report"


class IntelSource(StrEnum):
    """Sources of threat intelligence."""

    OSINT = "osint"
    COMMERCIAL_FEED = "commercial_feed"
    DARK_WEB = "dark_web"
    INTERNAL_TELEMETRY = "internal_telemetry"
    ISAC = "isac"
    GOVERNMENT = "government"


class ThreatRelevance(StrEnum):
    """Relevance levels for threats to the organization."""

    IMMEDIATE = "immediate"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    INFORMATIONAL = "informational"


class IntelligenceItem(BaseModel):
    """Raw intelligence item collected from a source."""

    item_id: str = ""
    source: IntelSource = IntelSource.OSINT
    raw_type: str = ""
    raw_value: str = ""
    raw_context: str = ""
    collected_at: datetime | None = None
    feed_name: str = ""
    tags: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    confidence_raw: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class NormalizedIndicator(BaseModel):
    """STIX/TAXII-normalized indicator of compromise."""

    indicator_id: str = ""
    stix_type: str = ""
    stix_pattern: str = ""
    value: str = ""
    indicator_types: list[str] = Field(default_factory=list)
    source: IntelSource = IntelSource.OSINT
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    kill_chain_phases: list[str] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)


class ThreatCorrelation(BaseModel):
    """Cross-source correlation linking indicators."""

    correlation_id: str = ""
    indicator_ids: list[str] = Field(default_factory=list)
    sources_matched: list[IntelSource] = Field(default_factory=list)
    internal_matches: list[dict[str, Any]] = Field(default_factory=list)
    match_count: int = 0
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    campaign_name: str = ""
    threat_actor: str = ""
    entities_affected: list[str] = Field(default_factory=list)


class RelevanceAssessment(BaseModel):
    """Assessment of threat relevance to customer env."""

    indicator_id: str = ""
    relevance: ThreatRelevance = ThreatRelevance.INFORMATIONAL
    relevance_score: float = Field(default=0.0, ge=0.0, le=1.0)
    actionable: bool = False
    exposure_vectors: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    ttl_hours: int = 24
    digital_risk_flags: list[str] = Field(default_factory=list)


class ThreatAdvisory(BaseModel):
    """Generated threat advisory for stakeholders."""

    advisory_id: str = ""
    title: str = ""
    severity: ThreatRelevance = ThreatRelevance.INFORMATIONAL
    summary: str = ""
    affected_indicators: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    distribution_targets: list[str] = Field(default_factory=list)
    generated_at: datetime | None = None


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ThreatIntelligencePlatformState(BaseModel):
    """Full LangGraph state for the TIP agent."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: IntelStage = IntelStage.COLLECT
    sources: list[IntelSource] = Field(default_factory=list)

    # Collection
    items_collected: list[IntelligenceItem] = Field(default_factory=list)

    # Normalization
    indicators_normalized: list[NormalizedIndicator] = Field(default_factory=list)

    # Correlation
    correlations: list[ThreatCorrelation] = Field(default_factory=list)

    # Assessment
    assessments: list[RelevanceAssessment] = Field(default_factory=list)

    # Advisories
    advisories_generated: list[ThreatAdvisory] = Field(default_factory=list)

    # Metrics
    actionable_intel_count: int = 0
    high_priority_count: int = 0
    confidence_score: float = 0.0

    # Metadata
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
