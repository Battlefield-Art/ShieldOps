"""Threat Response Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ResponseStage(StrEnum):
    CLASSIFY_THREAT = "classify_threat"
    SELECT_PLAYBOOK = "select_playbook"
    EXECUTE_CONTAINMENT = "execute_containment"
    EXECUTE_ERADICATION = "execute_eradication"
    VERIFY_REMEDIATION = "verify_remediation"
    REPORT = "report"


class ThreatSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ActionStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ThreatIndicator(BaseModel):
    """An indicator of a threat."""

    id: str = ""
    indicator_type: str = ""
    value: str = ""
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    source: str = ""
    mitre_tactic: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    first_seen: datetime | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class Playbook(BaseModel):
    """A threat response playbook."""

    id: str = ""
    name: str = ""
    threat_types: list[str] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
    auto_executable: bool = False
    estimated_time_min: int = 0
    description: str = ""
    severity_threshold: ThreatSeverity = ThreatSeverity.MEDIUM


class ContainmentAction(BaseModel):
    """A containment action taken during response."""

    id: str = ""
    action_type: str = ""
    target: str = ""
    status: ActionStatus = ActionStatus.PENDING
    details: str = ""
    executed_at: datetime | None = None
    reversible: bool = True


class EradicationAction(BaseModel):
    """An eradication action to remove the threat."""

    id: str = ""
    action_type: str = ""
    target: str = ""
    status: ActionStatus = ActionStatus.PENDING
    details: str = ""
    executed_at: datetime | None = None


class RemediationVerification(BaseModel):
    """Verification that remediation was successful."""

    action_id: str = ""
    verified: bool = False
    method: str = ""
    result: str = ""
    verified_at: datetime | None = None
    residual_risk: str = ""


class ThreatResponseState(BaseModel):
    """Main state for the Threat Response agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: ResponseStage = ResponseStage.CLASSIFY_THREAT

    # Input threat indicators
    threat_indicators: list[dict[str, Any]] = Field(default_factory=list)

    # Classification
    threat_classification: str = ""
    threat_severity: str = ""

    # Playbook
    selected_playbook: dict[str, Any] = Field(default_factory=dict)

    # Actions
    containment_actions: list[dict[str, Any]] = Field(default_factory=list)
    eradication_actions: list[dict[str, Any]] = Field(default_factory=list)

    # Verifications
    verifications: list[dict[str, Any]] = Field(default_factory=list)

    # Report
    summary: str = ""
    total_indicators: int = 0
    actions_completed: int = 0
    threat_contained: bool = False

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
