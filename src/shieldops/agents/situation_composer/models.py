"""State models for the Situation Composer Agent LangGraph workflow."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ComposerStage(StrEnum):
    """Stage of the situation composition pipeline."""

    COLLECT = "collect"
    DEDUPLICATE = "deduplicate"
    CORRELATE = "correlate"
    BUILD_NARRATIVE = "build_narrative"
    RECOMMEND_ACTIONS = "recommend_actions"
    PUBLISH = "publish"


class AlertSeverity(StrEnum):
    """Severity classification for raw alerts."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SituationStatus(StrEnum):
    """Lifecycle status of a composed situation."""

    DRAFT = "draft"
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class KillChainPhase(StrEnum):
    """Lockheed Martin Cyber Kill Chain phases."""

    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class RawAlert(BaseModel):
    """A single vendor alert before deduplication."""

    id: str = ""
    vendor: str = ""
    alert_type: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    title: str = ""
    description: str = ""
    timestamp: str = ""
    source_ip: str = ""
    dest_ip: str = ""
    user: str = ""
    hostname: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)


class DeduplicatedAlert(BaseModel):
    """Alert after deduplication — merges duplicate/near-duplicate alerts."""

    id: str = ""
    canonical_alert_id: str = ""
    duplicate_count: int = 1
    vendors: list[str] = Field(default_factory=list)
    merged_data: dict[str, Any] = Field(default_factory=dict)
    first_seen: str = ""
    last_seen: str = ""


class CorrelationLink(BaseModel):
    """A link between correlated alerts."""

    id: str = ""
    alert_ids: list[str] = Field(default_factory=list)
    correlation_type: str = ""
    confidence: float = 0.0
    description: str = ""
    kill_chain_phase: KillChainPhase | None = None


class SituationNarrative(BaseModel):
    """Kill-chain narrative assembled from correlated alerts."""

    id: str = ""
    title: str = ""
    executive_summary: str = ""
    kill_chain_mapping: dict[str, list[str]] = Field(default_factory=dict)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    ioc_list: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class RecommendedAction(BaseModel):
    """A response action recommended for a situation."""

    id: str = ""
    action_type: str = ""
    target: str = ""
    description: str = ""
    risk_level: str = "medium"
    auto_executable: bool = False
    estimated_impact: str = ""


class Situation(BaseModel):
    """The composed situation — the primary output of this agent."""

    id: str = ""
    status: SituationStatus = SituationStatus.DRAFT
    severity: AlertSeverity = AlertSeverity.MEDIUM
    narrative: SituationNarrative | None = None
    alerts: list[str] = Field(default_factory=list)
    correlations: list[str] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    assigned_to: str = ""
    resolution: str = ""


class ReasoningStep(BaseModel):
    """Audit trail entry for the composition workflow."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SituationComposerState(BaseModel):
    """Full state for the Situation Composer LangGraph workflow."""

    # Identity
    request_id: str = ""
    stage: ComposerStage = ComposerStage.COLLECT

    # Pipeline data
    raw_alerts: list[RawAlert] = Field(default_factory=list)
    deduplicated_alerts: list[DeduplicatedAlert] = Field(default_factory=list)
    correlations: list[CorrelationLink] = Field(default_factory=list)
    narrative: SituationNarrative | None = None
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    situation: Situation | None = None

    # Metrics
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
