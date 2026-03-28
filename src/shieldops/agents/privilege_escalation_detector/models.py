"""Privilege Escalation Detector Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EscalationStage(StrEnum):
    COLLECT_EVENTS = "collect_events"
    CLASSIFY_ESCALATIONS = "classify_escalations"
    CORRELATE_IDENTITIES = "correlate_identities"
    ASSESS_RISK = "assess_risk"
    RESPOND = "respond"
    REPORT = "report"


class EscalationType(StrEnum):
    SUDO_ABUSE = "sudo_abuse"
    ROLE_CHANGE = "role_change"
    IAM_POLICY_MODIFICATION = "iam_policy_modification"
    SERVICE_ACCOUNT_ELEVATION = "service_account_elevation"
    PRIVILEGE_BOUNDARY_BYPASS = "privilege_boundary_bypass"
    TOKEN_PRIVILEGE_ESCALATION = "token_privilege_escalation"  # noqa: S105


class ThreatSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EscalationEvent(BaseModel):
    """A single privilege escalation event from a source system."""

    id: str = ""
    principal_id: str = ""
    principal_type: str = ""
    source_system: str = ""
    action: str = ""
    target_resource: str = ""
    previous_privilege: str = ""
    new_privilege: str = ""
    timestamp: float = 0.0
    geo_location: str = ""
    risk_indicators: list[str] = Field(default_factory=list)


class EscalationFinding(BaseModel):
    """A classified privilege escalation finding."""

    id: str = ""
    escalation_type: EscalationType = EscalationType.SUDO_ABUSE
    principal_id: str = ""
    source_system: str = ""
    target_resource: str = ""
    privilege_delta: str = ""
    confidence: float = 0.0
    mitre_technique: str = ""
    timeline: list[dict[str, Any]] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    """Risk assessment for a detected privilege escalation."""

    id: str = ""
    finding_id: str = ""
    severity: ThreatSeverity = ThreatSeverity.LOW
    affected_resources: list[str] = Field(default_factory=list)
    affected_identities: list[str] = Field(default_factory=list)
    blast_radius: int = 0
    containment_actions: list[str] = Field(default_factory=list)


class ResponseAction(BaseModel):
    """A response action taken against a privilege escalation."""

    id: str = ""
    finding_id: str = ""
    action_type: str = ""
    target: str = ""
    description: str = ""
    auto_executed: bool = False
    success: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class PrivilegeEscalationDetectorState(BaseModel):
    """Main state for the Privilege Escalation Detector graph."""

    # Input
    request_id: str = ""
    stage: EscalationStage = EscalationStage.COLLECT_EVENTS
    tenant_id: str = ""
    time_window_hours: int = 24

    # Detection pipeline
    escalation_events: list[dict[str, Any]] = Field(default_factory=list)
    escalation_findings: list[dict[str, Any]] = Field(default_factory=list)
    risk_assessments: list[dict[str, Any]] = Field(default_factory=list)
    response_actions: list[dict[str, Any]] = Field(default_factory=list)

    # Stats & workflow
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
