"""MFA Bypass Detector Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MBDStage(StrEnum):
    COLLECT_AUTH_EVENTS = "collect_auth_events"
    ANALYZE_PATTERNS = "analyze_patterns"
    DETECT_BYPASS = "detect_bypass"
    ASSESS_RISK = "assess_risk"
    REMEDIATE = "remediate"
    REPORT = "report"


class BypassTechnique(StrEnum):
    MFA_FATIGUE = "mfa_fatigue"
    SESSION_HIJACK = "session_hijack"
    SIM_SWAP = "sim_swap"
    PUSH_ABUSE = "push_abuse"
    TOKEN_THEFT = "token_theft"
    PHISHING_RELAY = "phishing_relay"


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuthEvent(BaseModel):
    """A single authentication event."""

    id: str = ""
    timestamp: str = ""
    user_id: str = ""
    email: str = ""
    source_ip: str = ""
    geo_location: str = ""
    mfa_method: str = ""
    mfa_result: str = ""
    login_result: str = ""
    device_fingerprint: str = ""
    user_agent: str = ""


class AuthPattern(BaseModel):
    """An observed authentication pattern."""

    id: str = ""
    user_id: str = ""
    total_attempts: int = 0
    failed_mfa_count: int = 0
    unique_ips: int = 0
    unique_geos: int = 0
    avg_attempt_interval_sec: float = 0.0
    rapid_push_count: int = 0
    session_anomaly_score: float = 0.0


class BypassAttempt(BaseModel):
    """A detected MFA bypass attempt."""

    id: str = ""
    user_id: str = ""
    technique: BypassTechnique = BypassTechnique.MFA_FATIGUE
    confidence: float = 0.0
    source_ip: str = ""
    evidence: list[str] = Field(default_factory=list)
    timeline: list[str] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    """Risk assessment for a bypass attempt."""

    id: str = ""
    bypass_id: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    impact_score: float = 0.0
    user_privilege_level: str = ""
    account_compromised: bool = False
    lateral_movement_risk: float = 0.0
    data_exposure_risk: float = 0.0


class Remediation(BaseModel):
    """Remediation action applied."""

    id: str = ""
    bypass_id: str = ""
    action: str = ""
    status: str = ""
    session_revoked: bool = False
    mfa_reset: bool = False
    user_notified: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class MFABypassDetectorState(BaseModel):
    """Main state for the MFA Bypass Detector agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: MBDStage = MBDStage.COLLECT_AUTH_EVENTS

    auth_events: list[AuthEvent] = Field(default_factory=list)
    patterns: list[AuthPattern] = Field(default_factory=list)
    bypass_attempts: list[BypassAttempt] = Field(
        default_factory=list,
    )
    risk_assessments: list[RiskAssessment] = Field(
        default_factory=list,
    )
    remediations: list[Remediation] = Field(
        default_factory=list,
    )

    report: str = ""
    total_events_analyzed: int = 0
    bypasses_detected: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
