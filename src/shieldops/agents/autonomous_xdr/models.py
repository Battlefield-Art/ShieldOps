"""State models for the Autonomous XDR Agent.

Vendor-neutral Extended Detection and Response — correlates
signals across endpoint, network, cloud, and identity sources
from ANY vendor (CrowdStrike, Defender, SentinelOne, Wiz, Okta,
etc.) without requiring a single-vendor sensor ecosystem.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class XDRStage(StrEnum):
    """Pipeline stages for autonomous XDR processing."""

    COLLECT_TELEMETRY = "collect_telemetry"
    NORMALIZE_SIGNALS = "normalize_signals"
    CORRELATE_CROSS_DOMAIN = "correlate_cross_domain"
    DETECT_CAMPAIGNS = "detect_campaigns"
    AUTO_INVESTIGATE = "auto_investigate"
    RESPOND = "respond"
    REPORT = "report"


class SignalDomain(StrEnum):
    """Security telemetry domains ingested by XDR."""

    ENDPOINT = "endpoint"
    NETWORK = "network"
    CLOUD = "cloud"
    IDENTITY = "identity"
    EMAIL = "email"
    IOT = "iot"


class CampaignSeverity(StrEnum):
    """Severity classification for detected campaigns."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ── Domain Models ───────────────────────────────────────────


class TelemetrySignal(BaseModel):
    """Raw telemetry signal from a vendor source."""

    id: str = ""
    vendor: str = ""
    domain: SignalDomain = SignalDomain.ENDPOINT
    event_type: str = ""
    severity: str = "medium"
    raw_data: dict[str, Any] = Field(default_factory=dict)
    source_ip: str = ""
    dest_ip: str = ""
    user: str = ""
    asset: str = ""
    timestamp: datetime | None = None


class NormalizedAlert(BaseModel):
    """Vendor-neutral OCSF-normalized alert."""

    id: str = ""
    original_signal_id: str = ""
    vendor: str = ""
    domain: SignalDomain = SignalDomain.ENDPOINT
    ocsf_category: str = ""
    ocsf_class: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    mitre_technique: str = ""
    mitre_tactic: str = ""
    entities: list[str] = Field(default_factory=list)
    description: str = ""
    timestamp: datetime | None = None


class CrossDomainCorrelation(BaseModel):
    """Correlation linking alerts across multiple domains."""

    id: str = ""
    alert_ids: list[str] = Field(default_factory=list)
    domains_involved: list[str] = Field(default_factory=list)
    vendors_involved: list[str] = Field(default_factory=list)
    shared_entities: list[str] = Field(default_factory=list)
    correlation_score: float = 0.0
    kill_chain_phase: str = ""
    description: str = ""


class CampaignDetection(BaseModel):
    """Detected multi-stage attack campaign."""

    id: str = ""
    name: str = ""
    severity: CampaignSeverity = CampaignSeverity.MEDIUM
    correlation_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    kill_chain_stages: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    blast_radius: int = 0
    confidence: float = 0.0
    description: str = ""


class InvestigationResult(BaseModel):
    """Result of automated investigation into a campaign."""

    id: str = ""
    campaign_id: str = ""
    root_cause: str = ""
    entry_point: str = ""
    lateral_path: list[str] = Field(default_factory=list)
    compromised_assets: list[str] = Field(default_factory=list)
    compromised_identities: list[str] = Field(default_factory=list)
    blast_radius_assessment: str = ""
    recommended_actions: list[str] = Field(default_factory=list)
    containment_urgency: str = "medium"
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
    )


# ── Reasoning & State ──────────────────────────────────────


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class AutonomousXDRState(BaseModel):
    """Full state for an autonomous XDR workflow run."""

    # Identity
    session_id: str = ""
    tenant_id: str = ""
    stage: XDRStage = XDRStage.COLLECT_TELEMETRY
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline data
    signals_collected: list[TelemetrySignal] = Field(
        default_factory=list,
    )
    normalized_alerts: list[NormalizedAlert] = Field(
        default_factory=list,
    )
    correlations_found: list[CrossDomainCorrelation] = Field(
        default_factory=list,
    )
    campaigns_detected: list[CampaignDetection] = Field(
        default_factory=list,
    )
    investigations_completed: list[InvestigationResult] = Field(
        default_factory=list,
    )
    auto_responses: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metrics
    detection_coverage_pct: float = 0.0
    domains_covered: list[str] = Field(default_factory=list)
    vendors_queried: list[str] = Field(default_factory=list)

    # Tracking
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
