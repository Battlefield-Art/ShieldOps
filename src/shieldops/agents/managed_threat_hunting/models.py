"""State models for the Managed Threat Hunting Agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class HuntingStage(StrEnum):
    """Stages in the managed threat hunting lifecycle."""

    GENERATE_LEADS = "generate_hunt_leads"
    COLLECT_TELEMETRY = "collect_telemetry"
    EXECUTE_HUNTS = "execute_hunts"
    ANALYZE_FINDINGS = "analyze_findings"
    ESCALATE_THREATS = "escalate_threats"
    REPORT = "report"


class HuntTechnique(StrEnum):
    """Technique used to conduct a threat hunt."""

    HYPOTHESIS_DRIVEN = "hypothesis_driven"
    IOC_SWEEP = "ioc_sweep"
    TTP_HUNT = "ttp_hunt"
    ANOMALY_HUNT = "anomaly_hunt"
    BEHAVIORAL_HUNT = "behavioral_hunt"


class ThreatAssessment(StrEnum):
    """Assessed threat confidence level."""

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    BENIGN = "benign"


# --- Domain models ---


class HuntLead(BaseModel):
    """A generated hunt lead based on threat intel."""

    lead_id: str = ""
    title: str = ""
    technique: HuntTechnique = HuntTechnique.HYPOTHESIS_DRIVEN
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    priority: str = "medium"
    hypothesis: str = ""
    data_sources_needed: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class TelemetryCollection(BaseModel):
    """Telemetry collected from one or more vendors."""

    collection_id: str = ""
    vendor: str = ""
    source_type: str = ""
    record_count: int = 0
    time_range_start: str = ""
    time_range_end: str = ""
    coverage_domains: list[str] = Field(default_factory=list)
    raw_summary: dict[str, Any] = Field(default_factory=dict)


class HuntExecution(BaseModel):
    """Result of executing a single hunt against telemetry."""

    execution_id: str = ""
    lead_id: str = ""
    technique: HuntTechnique = HuntTechnique.HYPOTHESIS_DRIVEN
    queries_run: int = 0
    hits: int = 0
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    duration_ms: int = 0
    status: str = "pending"


class HuntAnalysis(BaseModel):
    """Analysis of findings from one or more hunt executions."""

    analysis_id: str = ""
    lead_id: str = ""
    assessment: ThreatAssessment = ThreatAssessment.BENIGN
    severity: str = "low"
    confidence: float = 0.0
    affected_assets: list[str] = Field(default_factory=list)
    mitre_mapping: list[str] = Field(default_factory=list)
    evidence_summary: str = ""
    recommended_actions: list[str] = Field(default_factory=list)


class ThreatEscalation(BaseModel):
    """An escalated threat for SOC / IR attention."""

    escalation_id: str = ""
    analysis_id: str = ""
    assessment: ThreatAssessment = ThreatAssessment.PROBABLE
    severity: str = "high"
    title: str = ""
    narrative: str = ""
    evidence_package: dict[str, Any] = Field(default_factory=dict)
    recommended_response: list[str] = Field(default_factory=list)
    escalated_to: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """Audit trail entry for the hunting workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ManagedThreatHuntingState(BaseModel):
    """Full state for the managed threat hunting workflow."""

    # Input
    tenant_id: str = ""
    hunt_campaign_id: str = ""
    hunt_scope: dict[str, Any] = Field(default_factory=dict)
    vendor_sources: list[str] = Field(default_factory=list)

    # Pipeline data
    hunt_leads: list[HuntLead] = Field(default_factory=list)
    telemetry_collected: list[TelemetryCollection] = Field(
        default_factory=list,
    )
    hunts_executed: list[HuntExecution] = Field(
        default_factory=list,
    )
    findings: list[HuntAnalysis] = Field(default_factory=list)
    escalations: list[ThreatEscalation] = Field(
        default_factory=list,
    )

    # Metrics
    threats_found: int = 0
    hunts_per_day: float = 0.0
    coverage_pct: float = 0.0

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
