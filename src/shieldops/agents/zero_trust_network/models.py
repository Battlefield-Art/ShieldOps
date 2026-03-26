"""Zero Trust Network Access — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ZTNAStage(StrEnum):
    DISCOVER_ACCESS_POINTS = "discover_access_points"
    ASSESS_IDENTITY_TRUST = "assess_identity_trust"
    EVALUATE_DEVICE_POSTURE = "evaluate_device_posture"
    ENFORCE_POLICIES = "enforce_policies"
    MONITOR_SESSIONS = "monitor_sessions"
    REPORT = "report"


class IdentityType(StrEnum):
    HUMAN = "human"
    SERVICE_ACCOUNT = "service_account"
    AI_AGENT = "ai_agent"
    API_KEY = "api_key"
    MCP_CLIENT = "mcp_client"


class TrustDecision(StrEnum):
    ALLOW = "allow"
    CHALLENGE = "challenge"
    RESTRICT = "restrict"
    DENY = "deny"
    QUARANTINE = "quarantine"


class AccessPoint(BaseModel):
    """A discovered network/API/MCP access point."""

    access_point_id: str = ""
    name: str = ""
    endpoint: str = ""
    protocol: str = ""
    identity_types_allowed: list[str] = Field(default_factory=list)
    auth_method: str = ""
    encryption: str = ""
    exposed: bool = False
    risk_score: float = 0.0


class IdentityTrustScore(BaseModel):
    """Trust score for an identity (human, agent, or NHI)."""

    identity_id: str = ""
    identity_type: IdentityType = IdentityType.HUMAN
    display_name: str = ""
    trust_score: float = 0.0
    behavioral_score: float = 0.0
    credential_score: float = 0.0
    history_score: float = 0.0
    last_verified: float = 0.0
    mfa_enabled: bool = False
    anomalies: list[str] = Field(default_factory=list)
    decision: TrustDecision = TrustDecision.DENY


class DevicePosture(BaseModel):
    """Device/runtime posture assessment."""

    device_id: str = ""
    identity_id: str = ""
    os_type: str = ""
    os_patched: bool = False
    agent_runtime: str = ""
    encryption_enabled: bool = False
    compliant: bool = False
    posture_score: float = 0.0
    issues: list[str] = Field(default_factory=list)


class PolicyEnforcement(BaseModel):
    """Result of a zero trust policy enforcement."""

    policy_id: str = ""
    identity_id: str = ""
    access_point_id: str = ""
    decision: TrustDecision = TrustDecision.DENY
    reason: str = ""
    conditions: list[str] = Field(default_factory=list)
    enforced_at: float = 0.0


class SessionMonitor(BaseModel):
    """Active session being continuously monitored."""

    session_id: str = ""
    identity_id: str = ""
    identity_type: IdentityType = IdentityType.HUMAN
    access_point_id: str = ""
    started_at: float = 0.0
    last_activity: float = 0.0
    trust_score: float = 0.0
    requests_count: int = 0
    anomaly_count: int = 0
    status: str = "active"


class ZeroTrustNetworkState(BaseModel):
    """Main state for the Zero Trust Network Access graph."""

    # Input
    tenant_id: str = ""
    scope: str = "full"
    identity_filter: str = ""

    # Discovery
    access_points: list[dict[str, Any]] = Field(default_factory=list)

    # Identity trust
    identity_scores: list[dict[str, Any]] = Field(default_factory=list)

    # Device posture
    device_postures: list[dict[str, Any]] = Field(default_factory=list)

    # Policy enforcement
    enforcements: list[dict[str, Any]] = Field(default_factory=list)

    # Session monitoring
    active_sessions: list[dict[str, Any]] = Field(default_factory=list)

    # Aggregate
    zero_trust_score: float = 0.0
    denied_count: int = 0
    challenged_count: int = 0
    quarantined_count: int = 0

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
