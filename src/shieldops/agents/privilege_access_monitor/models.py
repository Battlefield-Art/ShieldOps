"""State models for the Privilege Access Monitor Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class PAMStage(StrEnum):
    """Stages in the privilege access monitoring lifecycle."""

    DISCOVER_ACCOUNTS = "discover_accounts"
    AUDIT_SESSIONS = "audit_sessions"
    DETECT_ABUSE = "detect_abuse"
    ASSESS_RISK = "assess_risk"
    ENFORCE_JIT = "enforce_jit"
    REPORT = "report"


class AccountType(StrEnum):
    """Types of privileged accounts."""

    ROOT = "root"
    DOMAIN_ADMIN = "domain_admin"
    SERVICE_ACCOUNT = "service_account"
    BREAK_GLASS = "break_glass"
    SHARED_ADMIN = "shared_admin"
    CLOUD_IAM = "cloud_iam"


class AbuseIndicator(StrEnum):
    """Indicators of privileged access abuse."""

    OFF_HOURS_ACCESS = "off_hours_access"
    UNUSUAL_COMMAND = "unusual_command"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SESSION_HIJACKING = "session_hijacking"


# --- Domain models ---


class PrivilegedAccount(BaseModel):
    """A discovered privileged account."""

    account_id: str = ""
    username: str = ""
    account_type: AccountType = AccountType.SERVICE_ACCOUNT
    platform: str = ""
    last_used: datetime | None = None
    mfa_enabled: bool = False
    session_recording: bool = False
    jit_enabled: bool = False
    risk_score: float = 0.0


class SessionAudit(BaseModel):
    """Audit record for a privileged session."""

    session_id: str = ""
    account_id: str = ""
    start_time: datetime | None = None
    end_time: datetime | None = None
    commands_executed: int = 0
    sensitive_commands: list[str] = Field(
        default_factory=list,
    )
    source_ip: str = ""
    destination: str = ""
    recording_available: bool = False


class AbuseDetection(BaseModel):
    """A detected privilege abuse event."""

    detection_id: str = ""
    account_id: str = ""
    indicator: AbuseIndicator = AbuseIndicator.OFF_HOURS_ACCESS
    severity: str = "medium"
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str = ""


class RiskAssessment(BaseModel):
    """Risk assessment for a privileged account."""

    account_id: str = ""
    risk_score: float = 0.0
    risk_factors: list[str] = Field(default_factory=list)
    standing_access: bool = False
    jit_eligible: bool = False
    recommendation: str = ""


class JITEnforcement(BaseModel):
    """JIT access enforcement action."""

    enforcement_id: str = ""
    account_id: str = ""
    action: str = ""
    previous_state: str = ""
    new_state: str = ""
    ttl_minutes: int = 0
    approved_by: str = ""


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the monitor workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class PrivilegeAccessMonitorState(BaseModel):
    """Full state for a privilege access monitor run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: PAMStage = PAMStage.DISCOVER_ACCOUNTS

    # Inputs
    target_platforms: list[str] = Field(
        default_factory=list,
    )
    scope: dict[str, Any] = Field(default_factory=dict)
    audit_window_hours: int = 24

    # Pipeline fields
    accounts: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    sessions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    detections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    jit_enforcements: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_accounts: int = 0
    abuse_detected: int = 0
    jit_enforced: int = 0
    high_risk_count: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
