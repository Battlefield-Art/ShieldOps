"""State models for the Agentic MDR LangGraph workflow."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MDRStage(StrEnum):
    """Pipeline stage for the Agentic MDR workflow."""

    INGEST = "ingest_alerts"
    TRIAGE = "auto_triage"
    INVESTIGATE = "investigate"
    DECIDE = "decide_response"
    EXECUTE = "execute_response"
    VALIDATE = "validate_and_learn"
    REPORT = "report"


class ResponseDecision(StrEnum):
    """Outcome of the decision gate."""

    AUTO_REMEDIATE = "auto_remediate"
    HUMAN_APPROVE = "human_approve"
    ESCALATE = "escalate"
    SUPPRESS = "suppress"


class InvestigationDepth(StrEnum):
    """Depth of investigation to perform."""

    SHALLOW = "shallow"
    STANDARD = "standard"
    DEEP = "deep"
    FORENSIC = "forensic"


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


class AlertIngestion(BaseModel):
    """A raw alert ingested from a vendor source."""

    alert_id: str = ""
    vendor: str = ""
    original_id: str = ""
    severity: str = "medium"
    title: str = ""
    description: str = ""
    timestamp: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    hostname: str = ""
    user: str = ""
    mitre_technique: str = ""
    confidence: float = 0.0
    raw_data: dict[str, Any] = Field(default_factory=dict)


class TriageResult(BaseModel):
    """Output of the auto-triage stage."""

    alert_id: str = ""
    priority: str = "medium"
    confidence: float = 0.0
    decision: ResponseDecision = ResponseDecision.HUMAN_APPROVE
    investigation_depth: InvestigationDepth = InvestigationDepth.STANDARD
    reasoning: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    suppressed: bool = False


class InvestigationFinding(BaseModel):
    """A finding produced during investigation."""

    finding_id: str = ""
    alert_ids: list[str] = Field(default_factory=list)
    vendors_correlated: list[str] = Field(default_factory=list)
    description: str = ""
    severity: str = "medium"
    kill_chain_phase: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    ioc_indicators: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    enrichment: dict[str, Any] = Field(default_factory=dict)


class ResponseAction(BaseModel):
    """An action taken (or proposed) during response."""

    action_id: str = ""
    finding_id: str = ""
    action_type: str = ""
    vendor: str = ""
    target: str = ""
    description: str = ""
    decision: ResponseDecision = ResponseDecision.HUMAN_APPROVE
    status: str = "pending"
    result: dict[str, Any] = Field(default_factory=dict)
    started_at: str = ""
    completed_at: str = ""
    error: str | None = None


class ValidationResult(BaseModel):
    """Outcome of post-response validation."""

    action_id: str = ""
    validated: bool = False
    residual_risk: str = "unknown"
    lessons_learned: str = ""
    feedback_score: float = 0.0


class ClosedLoopImprovement(BaseModel):
    """A closed-loop learning record fed back into triage."""

    improvement_id: str = ""
    source_alert_id: str = ""
    original_decision: str = ""
    actual_outcome: str = ""
    triage_accuracy_delta: float = 0.0
    rule_update: str = ""
    created_at: str = ""


# ---------------------------------------------------------------------------
# Workflow state
# ---------------------------------------------------------------------------


class AgenticMDRState(BaseModel):
    """Full state for an Agentic MDR workflow run."""

    # Identifiers
    tenant_id: str = ""
    session_id: str = ""
    current_stage: str = "init"

    # Ingestion
    raw_alerts: list[dict[str, Any]] = Field(default_factory=list)
    ingested_alerts: list[AlertIngestion] = Field(default_factory=list)
    vendor_sources: list[str] = Field(default_factory=list)
    alert_count: int = 0

    # Triage
    triage_results: list[TriageResult] = Field(default_factory=list)

    # Investigation
    investigation_depth: InvestigationDepth = InvestigationDepth.STANDARD
    findings: list[InvestigationFinding] = Field(default_factory=list)

    # Response
    response_actions: list[ResponseAction] = Field(default_factory=list)
    escalations: list[dict[str, Any]] = Field(default_factory=list)

    # Validation & learning
    validation_results: list[ValidationResult] = Field(default_factory=list)
    closed_loop_improvements: list[ClosedLoopImprovement] = Field(default_factory=list)

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Metrics
    mean_time_to_respond_seconds: float = 0.0
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str | None = None
