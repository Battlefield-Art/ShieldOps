"""Lateral Movement Detector Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DetectorStage(StrEnum):
    COLLECT_SIGNALS = "collect_signals"
    ANALYZE_PATHS = "analyze_paths"
    DETECT_PIVOTS = "detect_pivots"
    ASSESS_BLAST_RADIUS = "assess_blast_radius"
    RESPOND = "respond"
    REPORT = "report"


class MovementType(StrEnum):
    OAUTH_TOKEN_REUSE = "oauth_token_reuse"  # noqa: S105
    SERVICE_ACCOUNT_PIVOT = "service_account_pivot"
    CROSS_CLOUD_ESCALATION = "cross_cloud_escalation"
    FEDERATION_ABUSE = "federation_abuse"
    DELEGATION_CHAIN = "delegation_chain"
    CREDENTIAL_RELAY = "credential_relay"


class MovementSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IdentitySignal(BaseModel):
    """A single identity-related security signal from a cloud provider."""

    id: str = ""
    identity_id: str = ""
    identity_type: str = ""
    source_cloud: str = ""
    action: str = ""
    target_resource: str = ""
    timestamp: float = 0.0
    geo_location: str = ""
    risk_indicators: list[str] = Field(default_factory=list)


class MovementPath(BaseModel):
    """A detected lateral movement path across identities or clouds."""

    id: str = ""
    movement_type: MovementType = MovementType.OAUTH_TOKEN_REUSE
    source_identity: str = ""
    target_identity: str = ""
    source_cloud: str = ""
    target_cloud: str = ""
    hops: int = 0
    confidence: float = 0.0
    mitre_technique: str = ""
    timeline: list[dict[str, Any]] = Field(default_factory=list)


class BlastRadiusAssessment(BaseModel):
    """Impact assessment for a detected lateral movement path."""

    id: str = ""
    path_id: str = ""
    affected_resources: list[str] = Field(default_factory=list)
    affected_identities: list[str] = Field(default_factory=list)
    data_at_risk: list[str] = Field(default_factory=list)
    severity: MovementSeverity = MovementSeverity.LOW
    containment_actions: list[str] = Field(default_factory=list)


class ResponseAction(BaseModel):
    """A response action taken against a detected lateral movement path."""

    id: str = ""
    path_id: str = ""
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


class LateralMovementState(BaseModel):
    """Main state for the Lateral Movement Detector graph."""

    # Input
    request_id: str = ""
    stage: DetectorStage = DetectorStage.COLLECT_SIGNALS
    tenant_id: str = ""
    time_window_hours: int = 24

    # Detection pipeline
    identity_signals: list[dict[str, Any]] = Field(default_factory=list)
    movement_paths: list[dict[str, Any]] = Field(default_factory=list)
    blast_radius_assessments: list[dict[str, Any]] = Field(default_factory=list)
    response_actions: list[dict[str, Any]] = Field(default_factory=list)

    # Stats & workflow
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
