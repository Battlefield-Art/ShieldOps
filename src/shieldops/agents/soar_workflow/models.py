"""SOAR Workflow Orchestrator Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ResponseStage(StrEnum):
    INTAKE = "intake"
    ENRICH = "enrich"
    CONTAIN = "contain"
    ERADICATE = "eradicate"
    RECOVER = "recover"
    LESSONS_LEARNED = "lessons_learned"


class PlaybookType(StrEnum):
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    NOTIFICATION = "notification"
    FORENSIC = "forensic"


class ResponseStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ESCALATED = "escalated"


class AlertIntake(BaseModel):
    """Normalized incoming security alert."""

    alert_id: str = ""
    source: str = ""
    severity: str = "medium"
    description: str = ""
    indicators: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)


class EnrichmentResult(BaseModel):
    """Enrichment data for a single indicator."""

    indicator: str = ""
    enrichment_type: str = ""
    result: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class ResponseAction(BaseModel):
    """A single response action executed during a SOAR workflow."""

    action_id: str = ""
    playbook_type: PlaybookType = PlaybookType.CONTAINMENT
    target: str = ""
    status: ResponseStatus = ResponseStatus.PENDING
    result: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int = Field(default=0, ge=0)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SOARWorkflowState(BaseModel):
    """Main state for the SOAR Workflow Orchestrator agent graph."""

    request_id: str = ""
    stage: ResponseStage = ResponseStage.INTAKE

    # Alert
    alert: dict[str, Any] = Field(default_factory=dict)

    # Enrichments
    enrichments: list[dict[str, Any]] = Field(default_factory=list)

    # Response actions
    actions: list[dict[str, Any]] = Field(default_factory=list)

    # Stage statuses
    containment_status: str = ""
    eradication_status: str = ""
    recovery_status: str = ""

    # Lessons learned
    lessons: list[str] = Field(default_factory=list)

    # Metrics
    total_response_time_ms: int = Field(default=0, ge=0)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
