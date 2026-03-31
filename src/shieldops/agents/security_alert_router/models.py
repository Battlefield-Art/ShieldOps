"""State models for the Security Alert Router Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class SARStage(StrEnum):
    """Stages in the security alert routing lifecycle."""

    RECEIVE_ALERTS = "receive_alerts"
    CLASSIFY = "classify"
    DETERMINE_OWNER = "determine_owner"
    ROUTE_ALERT = "route_alert"
    TRACK_ACK = "track_ack"
    REPORT = "report"


class AlertCategory(StrEnum):
    """Categories for security alerts."""

    MALWARE = "malware"
    INTRUSION = "intrusion"
    DATA_LEAK = "data_leak"
    POLICY_VIOLATION = "policy_violation"
    ANOMALY = "anomaly"
    COMPLIANCE = "compliance"


class RoutingPriority(StrEnum):
    """Routing priority levels."""

    P1_CRITICAL = "p1_critical"
    P2_HIGH = "p2_high"
    P3_MEDIUM = "p3_medium"
    P4_LOW = "p4_low"
    P5_INFO = "p5_info"
    SUPPRESSED = "suppressed"


# --- Domain models ---


class SecurityAlert(BaseModel):
    """A raw security alert received for routing."""

    alert_id: str = ""
    source: str = ""
    title: str = ""
    description: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime | None = None


class AlertClassification(BaseModel):
    """Classification result for an alert."""

    alert_id: str = ""
    category: AlertCategory = AlertCategory.ANOMALY
    priority: RoutingPriority = RoutingPriority.P3_MEDIUM
    confidence: float = 0.0
    tags: list[str] = Field(default_factory=list)


class OwnerAssignment(BaseModel):
    """Owner assignment for an alert."""

    alert_id: str = ""
    team: str = ""
    individual: str = ""
    escalation_path: list[str] = Field(
        default_factory=list,
    )
    sla_minutes: int = 60


class RoutingRecord(BaseModel):
    """Record of an alert routing decision."""

    alert_id: str = ""
    destination: str = ""
    channel: str = ""
    priority: RoutingPriority = RoutingPriority.P3_MEDIUM
    routed_at: datetime | None = None


class AcknowledgmentTracker(BaseModel):
    """Tracking acknowledgment of routed alerts."""

    alert_id: str = ""
    acknowledged: bool = False
    ack_by: str = ""
    ack_at: datetime | None = None
    response_minutes: int = 0


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the router workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityAlertRouterState(BaseModel):
    """Full state for a security alert router run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: SARStage = SARStage.RECEIVE_ALERTS

    # Inputs
    alert_sources: list[str] = Field(
        default_factory=list,
    )
    scope: dict[str, Any] = Field(default_factory=dict)
    routing_rules: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Pipeline fields
    alerts: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    owner_assignments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    routing_records: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    acknowledgments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_alerts: int = 0
    routed_count: int = 0
    acked_count: int = 0
    avg_response_minutes: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
