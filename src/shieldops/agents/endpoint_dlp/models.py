"""Endpoint DLP Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EndpointDLPStage(StrEnum):
    MONITOR_ENDPOINTS = "monitor_endpoints"
    DETECT_DATA_MOVEMENT = "detect_data_movement"
    CLASSIFY_SENSITIVITY = "classify_sensitivity"
    ENFORCE_POLICIES = "enforce_policies"
    INVESTIGATE_VIOLATIONS = "investigate_violations"
    REPORT = "report"


class DataMovementType(StrEnum):
    CLIPBOARD = "clipboard"
    USB = "usb"
    PRINT = "print"
    UPLOAD = "upload"
    EMAIL_ATTACHMENT = "email_attachment"
    AI_PROMPT_PASTE = "ai_prompt_paste"
    SCREEN_CAPTURE = "screen_capture"


class PolicyAction(StrEnum):
    ALLOW = "allow"
    LOG = "log"
    WARN = "warn"
    BLOCK = "block"
    ENCRYPT = "encrypt"


class EndpointActivity(BaseModel):
    """Endpoint activity monitoring record."""

    id: str = ""
    endpoint_id: str = ""
    hostname: str = ""
    user: str = ""
    os: str = ""
    agent_version: str = ""
    online: bool = True
    events_count: int = 0
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)


class DataMovement(BaseModel):
    """Detected data movement event."""

    id: str = ""
    endpoint_id: str = ""
    movement_type: DataMovementType = DataMovementType.CLIPBOARD
    source_app: str = ""
    destination: str = ""
    data_size_bytes: int = 0
    timestamp: str = ""
    user: str = ""
    suspicious: bool = False


class SensitivityClassification(BaseModel):
    """Sensitivity classification of moved data."""

    movement_id: str = ""
    sensitivity: str = ""
    data_types: list[str] = Field(default_factory=list)
    pii_detected: bool = False
    source_code_detected: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    context: str = ""


class PolicyEnforcement(BaseModel):
    """Policy enforcement result for a movement."""

    movement_id: str = ""
    policy_name: str = ""
    action: PolicyAction = PolicyAction.ALLOW
    reason: str = ""
    override_allowed: bool = False
    escalated: bool = False


class ViolationInvestigation(BaseModel):
    """Investigation of a policy violation."""

    movement_id: str = ""
    endpoint_id: str = ""
    user: str = ""
    violation_type: str = ""
    severity: str = ""
    timeline: list[str] = Field(default_factory=list)
    recommended_action: str = ""
    evidence: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class EndpointDLPState(BaseModel):
    """Main state for the Endpoint DLP agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: EndpointDLPStage = EndpointDLPStage.MONITOR_ENDPOINTS

    # Endpoint activities
    activities: list[EndpointActivity] = Field(default_factory=list)

    # Data movements
    movements: list[DataMovement] = Field(default_factory=list)

    # Sensitivity classifications
    classifications: list[SensitivityClassification] = Field(default_factory=list)

    # Policy enforcements
    enforcements: list[PolicyEnforcement] = Field(default_factory=list)

    # Violation investigations
    investigations: list[ViolationInvestigation] = Field(default_factory=list)

    # Summary
    report: str = ""
    total_endpoints: int = 0
    movements_blocked: int = 0
    violations_count: int = 0

    # Reasoning
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)

    # Error
    error: str = ""
