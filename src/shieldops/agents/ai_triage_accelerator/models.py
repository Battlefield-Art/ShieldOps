"""State models for the AI Triage Accelerator Agent LangGraph workflow."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TriageStage(StrEnum):
    """Stages in the AI triage accelerator workflow."""

    BATCH_INGEST = "batch_ingest"
    PARALLEL_CLASSIFY = "parallel_classify"
    ENRICH_CONTEXT = "enrich_context"
    CONFIDENCE_SCORE = "confidence_score"
    ROUTE_DECISIONS = "route_decisions"
    REPORT = "report"


class Classification(StrEnum):
    """Alert classification labels."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class RoutingDecision(StrEnum):
    """Routing decisions for classified alerts."""

    AUTO_CLOSE = "auto_close"
    AUTO_REMEDIATE = "auto_remediate"
    ANALYST_REVIEW = "analyst_review"
    ESCALATE_URGENT = "escalate_urgent"


class AlertBatch(BaseModel):
    """A batch of alerts to triage."""

    id: str = ""
    tenant_id: str = ""
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    source: str = ""
    ingested_at: float = 0.0
    batch_size: int = 0


class ClassificationResult(BaseModel):
    """Result of classifying a single alert."""

    id: str = ""
    alert_id: str = ""
    classification: Classification = Classification.SUSPICIOUS
    confidence: float = 0.0
    reasoning: str = ""
    indicators: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)


class EnrichmentData(BaseModel):
    """Context enrichment data for an alert."""

    id: str = ""
    alert_id: str = ""
    threat_intel_hits: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    identity_context: dict[str, Any] = Field(
        default_factory=dict,
    )
    asset_criticality: str = ""
    historical_alerts: int = 0
    related_alerts: list[str] = Field(default_factory=list)
    enrichment_sources: list[str] = Field(default_factory=list)


class ConfidenceScore(BaseModel):
    """Confidence score with transparent reasoning."""

    id: str = ""
    alert_id: str = ""
    overall_score: float = 0.0
    classification_weight: float = 0.0
    enrichment_weight: float = 0.0
    historical_weight: float = 0.0
    reasoning_chain: list[str] = Field(default_factory=list)


class RoutingAction(BaseModel):
    """Routing action for a triaged alert."""

    id: str = ""
    alert_id: str = ""
    decision: RoutingDecision = RoutingDecision.ANALYST_REVIEW
    confidence: float = 0.0
    assigned_team: str = ""
    estimated_resolution_min: int = 0
    routing_reason: str = ""
    auto_action_taken: str = ""


class ReasoningStep(BaseModel):
    """Audit trail entry for the triage workflow."""

    step: str = ""
    detail: str = ""
    confidence: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class AITriageAcceleratorState(BaseModel):
    """Full state for the AI Triage Accelerator workflow."""

    # Session
    request_id: str = ""
    stage: TriageStage = TriageStage.BATCH_INGEST
    tenant_id: str = ""

    # Input
    alert_batch: AlertBatch = Field(
        default_factory=AlertBatch,
    )
    batch_size: int = 0

    # Classification
    classifications: list[ClassificationResult] = Field(
        default_factory=list,
    )

    # Enrichment
    enrichments: list[EnrichmentData] = Field(
        default_factory=list,
    )

    # Confidence
    confidence_scores: list[ConfidenceScore] = Field(
        default_factory=list,
    )

    # Routing
    routing_actions: list[RoutingAction] = Field(
        default_factory=list,
    )

    # Metrics
    accuracy_score: float = 0.0
    speedup_factor: float = 0.0
    false_positive_rate: float = 0.0

    # Stats & reporting
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning chain
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )

    # Workflow metadata
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: int = 0
    error: str = ""
