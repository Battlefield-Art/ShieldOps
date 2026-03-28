"""State models for the IR Playbook Engine Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IRStage(StrEnum):
    """Stages in the IR playbook workflow."""

    CLASSIFY_INCIDENT = "classify_incident"
    SELECT_PLAYBOOK = "select_playbook"
    EXECUTE_STEPS = "execute_steps"
    ADAPT_RESPONSE = "adapt_response"
    VALIDATE_CONTAINMENT = "validate_containment"
    REPORT = "report"


class IncidentType(StrEnum):
    """Incident type classification."""

    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    DATA_BREACH = "data_breach"
    INSIDER = "insider"
    PHISHING = "phishing"
    DDOS = "ddos"
    SUPPLY_CHAIN = "supply_chain"
    ACCOUNT_COMPROMISE = "account_compromise"


class PlaybookStatus(StrEnum):
    """Playbook execution status."""

    EXECUTING = "executing"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    ADAPTED = "adapted"


class IncidentClassification(BaseModel):
    """Result of incident type classification."""

    id: str = ""
    incident_id: str = ""
    incident_type: IncidentType = IncidentType.MALWARE
    severity: str = "medium"
    confidence: float = 0.0
    indicators: list[str] = Field(default_factory=list)
    reasoning: str = ""


class PlaybookSelection(BaseModel):
    """Selected playbook for the incident."""

    id: str = ""
    playbook_name: str = ""
    incident_type: IncidentType = IncidentType.MALWARE
    steps: list[dict[str, Any]] = Field(default_factory=list)
    estimated_duration_min: int = 0
    automation_level: str = "semi_automated"
    selection_reason: str = ""


class StepExecution(BaseModel):
    """Result of executing a single playbook step."""

    id: str = ""
    step_index: int = 0
    step_name: str = ""
    status: str = "pending"
    output: str = ""
    duration_ms: int = 0
    automated: bool = False
    error: str = ""


class ResponseAdaptation(BaseModel):
    """Mid-incident adaptation to the response plan."""

    id: str = ""
    trigger: str = ""
    original_step: str = ""
    adapted_step: str = ""
    reason: str = ""
    confidence: float = 0.0


class ContainmentValidation(BaseModel):
    """Validation that containment measures are effective."""

    id: str = ""
    check_name: str = ""
    passed: bool = False
    evidence: str = ""
    timestamp: float = 0.0


class IRPlaybookEngineState(BaseModel):
    """Full state for the IR Playbook Engine workflow."""

    request_id: str = ""
    stage: IRStage = IRStage.CLASSIFY_INCIDENT
    tenant_id: str = ""

    # Input
    incident: dict[str, Any] = Field(default_factory=dict)

    # Classification
    classification: IncidentClassification = Field(default_factory=IncidentClassification)

    # Playbook
    playbook: PlaybookSelection = Field(default_factory=PlaybookSelection)

    # Execution
    step_results: list[StepExecution] = Field(default_factory=list)

    # Adaptation
    adaptations: list[ResponseAdaptation] = Field(default_factory=list)

    # Containment
    containment_checks: list[ContainmentValidation] = Field(default_factory=list)

    # Stats & reporting
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)

    # Workflow metadata
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: int = 0
    error: str = ""
