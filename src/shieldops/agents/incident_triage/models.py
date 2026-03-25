"""State models for the Incident Triage Agent LangGraph workflow."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TriageStage(StrEnum):
    """Stages in the incident triage workflow."""

    INGEST = "ingest"
    CLASSIFY = "classify"
    ENRICH = "enrich"
    DEDUPLICATE = "deduplicate"
    ROUTE = "route"
    REPORT = "report"


class IncidentSeverity(StrEnum):
    """Standardized incident severity levels."""

    SEV1 = "sev1"
    SEV2 = "sev2"
    SEV3 = "sev3"
    SEV4 = "sev4"
    SEV5 = "sev5"


class IncidentCategory(StrEnum):
    """Incident category classification."""

    SECURITY_BREACH = "security_breach"
    AVAILABILITY = "availability"
    PERFORMANCE = "performance"
    DATA_LOSS = "data_loss"
    COMPLIANCE = "compliance"
    CONFIGURATION = "configuration"


class TriageConfidence(StrEnum):
    """Confidence level of the triage classification."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCERTAIN = "uncertain"


class IncomingIncident(BaseModel):
    """An incoming incident to be triaged."""

    id: str = ""
    title: str = ""
    description: str = ""
    source: str = ""
    raw_severity: str = ""
    timestamp: float = 0.0
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    affected_services: list[str] = Field(default_factory=list)


class SeverityClassification(BaseModel):
    """Result of severity classification for an incident."""

    id: str = ""
    incident_id: str = ""
    severity: IncidentSeverity = IncidentSeverity.SEV4
    category: IncidentCategory = IncidentCategory.CONFIGURATION
    confidence: TriageConfidence = TriageConfidence.UNCERTAIN
    reasoning: str = ""
    historical_similar: int = 0


class EnrichmentResult(BaseModel):
    """Context enrichment data for an incident."""

    id: str = ""
    incident_id: str = ""
    affected_customers: int = 0
    blast_radius: str = ""
    related_changes: list[str] = Field(default_factory=list)
    related_incidents: list[str] = Field(default_factory=list)
    runbook_url: str = ""
    on_call_team: str = ""


class RoutingDecision(BaseModel):
    """Routing decision for a triaged incident."""

    id: str = ""
    incident_id: str = ""
    assigned_team: str = ""
    escalation_required: bool = False
    auto_remediation_possible: bool = False
    estimated_ttm_minutes: int = 0
    routing_reason: str = ""


class ReasoningStep(BaseModel):
    """Audit trail entry for the triage workflow."""

    step: str = ""
    detail: str = ""
    confidence: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentTriageState(BaseModel):
    """Full state for an incident triage workflow run through the LangGraph workflow."""

    # Session
    request_id: str = ""
    stage: TriageStage = TriageStage.INGEST
    tenant_id: str = ""

    # Input
    incoming_incidents: list[IncomingIncident] = Field(default_factory=list)

    # Classification
    classifications: list[SeverityClassification] = Field(default_factory=list)

    # Enrichment
    enrichments: list[EnrichmentResult] = Field(default_factory=list)

    # Deduplication
    deduplicated_count: int = 0

    # Routing
    routing_decisions: list[RoutingDecision] = Field(default_factory=list)

    # Stats & reporting
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning chain
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)

    # Workflow metadata
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: int = 0
    error: str = ""
