"""State models for the Threat Landscape Analyzer Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class TLAStage(StrEnum):
    """Stages in the threat landscape analysis lifecycle."""

    COLLECT_INTEL = "collect_intel"
    ANALYZE_TRENDS = "analyze_trends"
    MAP_TO_INDUSTRY = "map_to_industry"
    BENCHMARK_POSTURE = "benchmark_posture"
    GENERATE_BRIEF = "generate_brief"
    REPORT = "report"


class IndustryVertical(StrEnum):
    """Industry vertical for threat landscape scoping."""

    FINANCIAL = "financial"
    HEALTHCARE = "healthcare"
    TECHNOLOGY = "technology"
    GOVERNMENT = "government"
    RETAIL = "retail"
    ENERGY = "energy"


class ThreatCategory(StrEnum):
    """Category of threat in the landscape."""

    RANSOMWARE = "ransomware"
    APT = "apt"
    SUPPLY_CHAIN = "supply_chain"
    INSIDER = "insider"
    ZERO_DAY = "zero_day"
    SOCIAL_ENGINEERING = "social_engineering"


# --- Domain models ---


class ThreatIntelItem(BaseModel):
    """A collected threat intelligence item."""

    intel_id: str = ""
    source: str = ""
    category: ThreatCategory = ThreatCategory.RANSOMWARE
    title: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    iocs: list[str] = Field(default_factory=list)
    published_at: datetime | None = None


class TrendAnalysis(BaseModel):
    """Analysis of threat trends over time."""

    trend_id: str = ""
    category: ThreatCategory = ThreatCategory.RANSOMWARE
    direction: str = "increasing"
    velocity: float = 0.0
    affected_sectors: list[str] = Field(default_factory=list)
    summary: str = ""


class IndustryMapping(BaseModel):
    """Mapping of threats to a specific industry."""

    industry: IndustryVertical = IndustryVertical.TECHNOLOGY
    relevant_threats: list[str] = Field(default_factory=list)
    attack_surface_factors: list[str] = Field(
        default_factory=list,
    )
    regulatory_context: list[str] = Field(
        default_factory=list,
    )
    risk_multiplier: float = 1.0


class PostureBenchmark(BaseModel):
    """Benchmark of security posture against peers."""

    benchmark_id: str = ""
    industry: IndustryVertical = IndustryVertical.TECHNOLOGY
    overall_score: float = 0.0
    peer_percentile: int = 50
    gaps: list[str] = Field(default_factory=list)
    strengths: list[str] = Field(default_factory=list)


class ThreatBrief(BaseModel):
    """Executive threat brief for leadership."""

    brief_id: str = ""
    title: str = ""
    executive_summary: str = ""
    top_threats: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(
        default_factory=list,
    )
    risk_rating: str = "medium"


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the analyzer workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ThreatLandscapeAnalyzerState(BaseModel):
    """Full state for a threat landscape analyzer run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: TLAStage = TLAStage.COLLECT_INTEL

    # Inputs
    industry: IndustryVertical = IndustryVertical.TECHNOLOGY
    time_range: str = "30d"
    scope: dict[str, Any] = Field(default_factory=dict)
    intel_sources: list[str] = Field(default_factory=list)

    # Pipeline fields
    intel_items: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    trends: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    industry_mapping: dict[str, Any] = Field(
        default_factory=dict,
    )
    benchmark: dict[str, Any] = Field(
        default_factory=dict,
    )
    threat_brief: dict[str, Any] = Field(
        default_factory=dict,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_threats: int = 0
    critical_threats: int = 0
    posture_score: float = 0.0
    peer_percentile: int = 50

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
