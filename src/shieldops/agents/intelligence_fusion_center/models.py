"""State models for the Intelligence Fusion Center Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IFCStage(StrEnum):
    """Stages of the intelligence fusion lifecycle."""

    COLLECT_FEEDS = "collect_feeds"
    CORRELATE_THREATS = "correlate_threats"
    FUSE_INTELLIGENCE = "fuse_intelligence"
    ASSESS_THREATS = "assess_threats"
    GENERATE_ASSESSMENT = "generate_assessment"
    REPORT = "report"


class IntelSource(StrEnum):
    """Sources of threat intelligence for fusion."""

    OSINT = "osint"
    COMMERCIAL_FEED = "commercial_feed"
    DARK_WEB = "dark_web"
    INTERNAL_TELEMETRY = "internal_telemetry"
    ISAC = "isac"
    GOVERNMENT = "government"
    HONEYPOT = "honeypot"
    PEER_EXCHANGE = "peer_exchange"


class ThreatLevel(StrEnum):
    """Threat severity levels after fusion analysis."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class IntelFeed(BaseModel):
    """Raw intelligence feed data collected from a source."""

    feed_id: str = ""
    source: IntelSource = IntelSource.OSINT
    feed_name: str = ""
    indicator_type: str = ""
    indicator_value: str = ""
    raw_context: str = ""
    collected_at: datetime | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CorrelatedThreat(BaseModel):
    """Cross-source correlated threat linking multiple indicators."""

    correlation_id: str = ""
    indicator_ids: list[str] = Field(default_factory=list)
    sources_matched: list[IntelSource] = Field(default_factory=list)
    match_count: int = 0
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    campaign_name: str = ""
    threat_actor: str = ""
    attack_pattern: str = ""
    entities_affected: list[str] = Field(default_factory=list)
    temporal_window_hours: int = 0


class FusionResult(BaseModel):
    """Result of fusing intelligence from multiple correlations."""

    fusion_id: str = ""
    correlated_threat_ids: list[str] = Field(default_factory=list)
    unified_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    threat_narrative: str = ""
    kill_chain_coverage: list[str] = Field(default_factory=list)
    diamond_model: dict[str, Any] = Field(default_factory=dict)
    source_agreement_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    fused_indicators: list[dict[str, Any]] = Field(default_factory=list)
    intelligence_gaps: list[str] = Field(default_factory=list)


class ThreatAssessment(BaseModel):
    """Final unified threat assessment after fusion."""

    assessment_id: str = ""
    fusion_id: str = ""
    threat_level: ThreatLevel = ThreatLevel.INFORMATIONAL
    overall_score: float = Field(default=0.0, ge=0.0, le=1.0)
    actionable: bool = False
    exposure_vectors: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    ttl_hours: int = 24


class FusionReport(BaseModel):
    """Summary report of a complete fusion cycle."""

    report_id: str = ""
    title: str = ""
    threat_level: ThreatLevel = ThreatLevel.INFORMATIONAL
    executive_summary: str = ""
    feeds_processed: int = 0
    threats_correlated: int = 0
    fusions_completed: int = 0
    assessments_generated: int = 0
    actionable_count: int = 0
    high_priority_count: int = 0
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


class IntelligenceFusionCenterState(BaseModel):
    """Full LangGraph state for the Intelligence Fusion Center agent."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: IFCStage = IFCStage.COLLECT_FEEDS
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    feeds_collected: list[dict[str, Any]] = Field(default_factory=list)
    correlated_threats: list[dict[str, Any]] = Field(default_factory=list)
    fusion_results: list[dict[str, Any]] = Field(default_factory=list)
    threat_assessments: list[dict[str, Any]] = Field(default_factory=list)
    assessment_output: list[dict[str, Any]] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)

    # Metrics
    actionable_count: int = 0
    high_priority_count: int = 0
    confidence_score: float = 0.0

    # Metadata
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
