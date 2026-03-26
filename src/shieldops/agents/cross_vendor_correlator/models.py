"""State models for the Cross-Vendor Correlator Agent."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CorrelationStage(StrEnum):
    """Stages of the cross-vendor correlation pipeline."""

    INGEST_VENDOR_ALERTS = "ingest_vendor_alerts"
    NORMALIZE_TO_OCSF = "normalize_to_ocsf"
    CORRELATE_BY_ENTITY = "correlate_by_entity"
    BUILD_KILL_CHAIN = "build_kill_chain"
    CREATE_SITUATIONS = "create_situations"
    REPORT = "report"


class VendorSource(StrEnum):
    """Supported vendor sources for alert ingestion."""

    CROWDSTRIKE = "crowdstrike"
    DEFENDER = "defender"
    WIZ = "wiz"
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    OKTA = "okta"
    CLOUDTRAIL = "cloudtrail"
    SENTINEL = "sentinel"


class CorrelationConfidence(StrEnum):
    """Confidence level for cross-vendor correlations."""

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    NONE = "none"


class VendorAlert(BaseModel):
    """Raw alert from a specific security vendor."""

    id: str = ""
    vendor: str = ""
    alert_type: str = ""
    severity: str = ""
    title: str = ""
    description: str = ""
    timestamp: float = 0.0
    entities: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class OCSFEvent(BaseModel):
    """Alert normalized to OCSF schema."""

    id: str = ""
    category_uid: int = 0
    class_uid: int = 0
    activity_id: int = 0
    severity_id: int = 0
    time: float = 0.0
    message: str = ""
    src_endpoint: str = ""
    dst_endpoint: str = ""
    actor_user: str = ""
    observables: list[str] = Field(default_factory=list)
    vendor_name: str = ""
    product_name: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)


class EntityCorrelation(BaseModel):
    """Correlation cluster grouped by shared entity."""

    id: str = ""
    entity: str = ""
    entity_type: str = ""
    event_ids: list[str] = Field(default_factory=list)
    vendors_involved: list[str] = Field(default_factory=list)
    confidence: CorrelationConfidence = CorrelationConfidence.NONE
    time_span_seconds: float = 0.0


class KillChainMapping(BaseModel):
    """MITRE ATT&CK kill chain mapping for correlated events."""

    id: str = ""
    correlation_id: str = ""
    tactic: str = ""
    technique_id: str = ""
    technique_name: str = ""
    events_mapped: list[str] = Field(default_factory=list)
    progression_score: float = 0.0


class Situation(BaseModel):
    """Unified situation created from correlated vendor alerts."""

    id: str = ""
    title: str = ""
    narrative: str = ""
    severity: str = ""
    kill_chain_stages: list[str] = Field(default_factory=list)
    correlation_ids: list[str] = Field(default_factory=list)
    vendor_count: int = 0
    event_count: int = 0
    recommended_actions: list[str] = Field(default_factory=list)
    confidence: CorrelationConfidence = CorrelationConfidence.NONE


class ReasoningStep(BaseModel):
    """Audit trail entry for the correlation workflow."""

    step_number: int = 0
    action: str = ""
    input_summary: str = ""
    output_summary: str = ""
    duration_ms: int = 0
    tool_used: str | None = None


class CrossVendorCorrelatorState(BaseModel):
    """Full state for a cross-vendor correlation run."""

    # Input
    tenant_id: str = ""
    vendors: list[str] = Field(default_factory=list)
    time_window_minutes: int = 60

    # Pipeline data
    vendor_alerts: list[VendorAlert] = Field(default_factory=list)
    ocsf_events: list[OCSFEvent] = Field(default_factory=list)
    correlations: list[EntityCorrelation] = Field(default_factory=list)
    kill_chain_mappings: list[KillChainMapping] = Field(default_factory=list)
    situations: list[Situation] = Field(default_factory=list)

    # Metrics
    total_alerts_ingested: int = 0
    total_situations_created: int = 0
    vendors_correlated: int = 0

    # Workflow tracking
    current_stage: CorrelationStage = CorrelationStage.INGEST_VENDOR_ALERTS
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str = ""
    session_duration_ms: int = 0
