"""State models for the Incident Playbook Engine LangGraph workflow."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IPEStage(StrEnum):
    """Stages in the incident playbook engine workflow."""

    CLASSIFY_INCIDENT = "classify_incident"
    SELECT_PLAYBOOK = "select_playbook"
    ADAPT_STEPS = "adapt_steps"
    EXECUTE_PLAYBOOK = "execute_playbook"
    VALIDATE_OUTCOME = "validate_outcome"
    REPORT = "report"


class IncidentCategory(StrEnum):
    """Incident category for playbook selection."""

    MALWARE = "malware"
    PHISHING = "phishing"
    INSIDER_THREAT = "insider_threat"
    DATA_BREACH = "data_breach"
    DDOS = "ddos"
    RANSOMWARE = "ransomware"
    SUPPLY_CHAIN = "supply_chain"


class PlaybookStatus(StrEnum):
    """Lifecycle status of a playbook execution."""

    DRAFT = "draft"
    ACTIVE = "active"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


class IncidentClassification(BaseModel):
    """Result of classifying an incoming incident."""

    id: str = ""
    category: IncidentCategory = IncidentCategory.MALWARE
    severity: str = "medium"
    confidence: float = 0.0
    indicators: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    reasoning: str = ""


class PlaybookSelection(BaseModel):
    """A candidate playbook selected for the incident."""

    id: str = ""
    name: str = ""
    category: IncidentCategory = IncidentCategory.MALWARE
    version: str = "1.0"
    match_score: float = 0.0
    historical_success_rate: float = 0.0
    avg_resolution_minutes: int = 0
    description: str = ""


class PlaybookStep(BaseModel):
    """A single step within a playbook execution plan."""

    id: str = ""
    order: int = 0
    action: str = ""
    description: str = ""
    tool: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 300
    requires_approval: bool = False
    rollback_action: str = ""
    status: str = "pending"
    result: str = ""
    duration_ms: int = 0


class PlaybookExecution(BaseModel):
    """Tracks the execution of a selected playbook."""

    id: str = ""
    playbook_id: str = ""
    status: PlaybookStatus = PlaybookStatus.DRAFT
    steps: list[PlaybookStep] = Field(default_factory=list)
    steps_completed: int = 0
    steps_failed: int = 0
    total_duration_ms: int = 0
    rollback_triggered: bool = False
    approval_pending: bool = False


class OutcomeValidation(BaseModel):
    """Validation result after playbook execution."""

    id: str = ""
    execution_id: str = ""
    success: bool = False
    threat_neutralized: bool = False
    residual_risk: str = "unknown"
    verification_checks: list[str] = Field(
        default_factory=list,
    )
    failed_checks: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    lessons_learned: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """Audit trail entry for the playbook engine workflow."""

    step: str = ""
    detail: str = ""
    confidence: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentPlaybookEngineState(BaseModel):
    """Full state for an incident playbook engine workflow run."""

    # Session
    request_id: str = ""
    stage: IPEStage = IPEStage.CLASSIFY_INCIDENT
    tenant_id: str = ""

    # Input
    alert_title: str = ""
    alert_description: str = ""
    alert_source: str = ""
    alert_severity: str = ""
    alert_indicators: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)

    # Classification
    classification: IncidentClassification = Field(
        default_factory=IncidentClassification,
    )

    # Playbook selection
    candidate_playbooks: list[PlaybookSelection] = Field(
        default_factory=list,
    )
    selected_playbook: PlaybookSelection = Field(
        default_factory=PlaybookSelection,
    )

    # Execution
    execution: PlaybookExecution = Field(
        default_factory=PlaybookExecution,
    )

    # Validation
    outcome: OutcomeValidation = Field(
        default_factory=OutcomeValidation,
    )

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
