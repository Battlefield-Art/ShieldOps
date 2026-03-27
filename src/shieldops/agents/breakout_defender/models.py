"""Breakout Defender Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DefenseStage(StrEnum):
    """Stages of the breakout defense workflow."""

    DETECT_INITIAL_ACCESS = "detect_initial_access"
    ANALYZE_LATERAL_MOVEMENT = "analyze_lateral_movement"
    ASSESS_BREAKOUT_RISK = "assess_breakout_risk"
    EXECUTE_CONTAINMENT = "execute_containment"
    VERIFY_CONTAINMENT = "verify_containment"
    REPORT = "report"


class BreakoutPhase(StrEnum):
    """Kill chain phases of an eCrime breakout attempt."""

    INITIAL_ACCESS = "initial_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_STAGING = "data_staging"
    EXFILTRATION = "exfiltration"


class ContainmentAction(StrEnum):
    """Automated containment actions for breakout response."""

    ISOLATE_HOST = "isolate_host"
    REVOKE_CREDENTIALS = "revoke_credentials"
    BLOCK_NETWORK = "block_network"
    DISABLE_ACCOUNT = "disable_account"
    QUARANTINE_PROCESS = "quarantine_process"


# --- Domain Models ---


class BreakoutSignal(BaseModel):
    """A signal indicating potential breakout activity."""

    signal_id: str = ""
    source: str = ""
    signal_type: str = ""
    phase: str = "initial_access"
    severity: str = "medium"
    confidence: float = 0.0
    hostname: str = ""
    ip_address: str = ""
    cloud_provider: str = ""
    user_identity: str = ""
    process_name: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    raw_event: dict[str, Any] = Field(default_factory=dict)
    timestamp: float = 0.0


class LateralMovementPath(BaseModel):
    """A detected lateral movement path across infrastructure."""

    path_id: str = ""
    source_host: str = ""
    target_host: str = ""
    source_cloud: str = ""
    target_cloud: str = ""
    pivot_type: str = ""
    credentials_used: list[str] = Field(default_factory=list)
    hops: list[dict[str, str]] = Field(
        default_factory=list,
    )
    risk_score: float = 0.0
    is_cross_cloud: bool = False


class ContainmentOrder(BaseModel):
    """An order to execute a containment action."""

    order_id: str = ""
    action: str = "isolate_host"
    target: str = ""
    target_type: str = ""
    cloud_provider: str = ""
    reason: str = ""
    confidence: float = 0.0
    requires_approval: bool = False
    executed: bool = False
    execution_time_ms: int = 0
    result: str = ""


class BreakoutReport(BaseModel):
    """Final report of a breakout defense engagement."""

    report_id: str = ""
    tenant_id: str = ""
    breakout_prevented: bool = False
    initial_phase_detected: str = ""
    furthest_phase_reached: str = ""
    time_to_detect_seconds: float = 0.0
    time_to_contain_seconds: float = 0.0
    signals_analyzed: int = 0
    lateral_paths_found: int = 0
    containment_actions_taken: int = 0
    mitre_techniques: list[str] = Field(
        default_factory=list,
    )
    summary: str = ""


class DefenseReasoningStep(BaseModel):
    """Audit trail entry for the breakout defense workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class BreakoutDefenderState(BaseModel):
    """Full state for a breakout defense run."""

    # Input
    tenant_id: str = ""
    defense_id: str = ""
    incoming_signals: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Detection
    signals: list[BreakoutSignal] = Field(
        default_factory=list,
    )
    initial_access_detected: bool = False
    detected_phase: str = ""

    # Lateral movement analysis
    paths: list[LateralMovementPath] = Field(
        default_factory=list,
    )
    cross_cloud_detected: bool = False

    # Risk assessment
    breakout_risk_score: float = 0.0
    estimated_breakout_time_minutes: float = 0.0
    auto_contain: bool = False

    # Containment
    containment_orders: list[ContainmentOrder] = Field(
        default_factory=list,
    )
    containment_executed: bool = False

    # Verification
    containment_verified: bool = False
    residual_risk: float = 0.0

    # Outcome
    time_to_contain_seconds: float = 0.0
    breakout_prevented: bool = False
    report: BreakoutReport | None = None

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[DefenseReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
