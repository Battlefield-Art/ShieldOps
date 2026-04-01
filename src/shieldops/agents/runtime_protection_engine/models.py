"""State models for the Runtime Protection Engine Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RPEStage(StrEnum):
    """Stages of the runtime protection lifecycle."""

    COLLECT_TELEMETRY = "collect_telemetry"
    ANALYZE_BEHAVIOR = "analyze_behavior"
    DETECT_ANOMALIES = "detect_anomalies"
    ENFORCE_POLICIES = "enforce_policies"
    GENERATE_ALERTS = "generate_alerts"
    REPORT = "report"


class BehaviorCategory(StrEnum):
    """Categories of observed agent runtime behavior."""

    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    ANOMALOUS = "anomalous"
    MALICIOUS = "malicious"
    POLICY_VIOLATION = "policy_violation"
    RATE_EXCEEDED = "rate_exceeded"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"


class EnforcementAction(StrEnum):
    """Actions taken by the runtime protection engine."""

    ALLOW = "allow"
    BLOCK = "block"
    THROTTLE = "throttle"
    QUARANTINE = "quarantine"
    ALERT_ONLY = "alert_only"
    REQUIRE_APPROVAL = "require_approval"
    TERMINATE_SESSION = "terminate_session"
    ROLLBACK = "rollback"


class RuntimeTelemetry(BaseModel):
    """Telemetry data collected from agent runtime."""

    telemetry_id: str = ""
    agent_id: str = ""
    agent_name: str = ""
    tool_call: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime | None = None
    latency_ms: int = 0
    token_count: int = 0
    resource_usage: dict[str, Any] = Field(default_factory=dict)
    session_id: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class BehaviorProfile(BaseModel):
    """Behavioral profile derived from telemetry analysis."""

    profile_id: str = ""
    agent_id: str = ""
    category: BehaviorCategory = BehaviorCategory.NORMAL
    tool_call_frequency: float = 0.0
    avg_latency_ms: float = 0.0
    resource_pattern: str = ""
    deviation_score: float = Field(default=0.0, ge=0.0, le=1.0)
    baseline_comparison: dict[str, Any] = Field(default_factory=dict)
    observed_patterns: list[str] = Field(default_factory=list)


class AnomalyDetection(BaseModel):
    """Anomaly detection result from behavior analysis."""

    anomaly_id: str = ""
    agent_id: str = ""
    anomaly_type: str = ""
    severity: str = "medium"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    mitre_technique: str = ""
    recommended_action: EnforcementAction = EnforcementAction.ALERT_ONLY


class PolicyEnforcement(BaseModel):
    """Policy enforcement action taken on a detected anomaly."""

    enforcement_id: str = ""
    anomaly_id: str = ""
    action: EnforcementAction = EnforcementAction.ALLOW
    policy_name: str = ""
    applied_at: datetime | None = None
    success: bool = True
    details: str = ""
    rollback_available: bool = False


class AlertOutput(BaseModel):
    """Alert generated from anomaly detection and enforcement."""

    alert_id: str = ""
    severity: str = "medium"
    title: str = ""
    description: str = ""
    agent_id: str = ""
    anomaly_ids: list[str] = Field(default_factory=list)
    enforcement_ids: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    created_at: datetime | None = None


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class RuntimeProtectionEngineState(BaseModel):
    """Full LangGraph state for the Runtime Protection Engine agent."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: RPEStage = RPEStage.COLLECT_TELEMETRY
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    telemetry: list[dict[str, Any]] = Field(default_factory=list)
    behaviors: list[dict[str, Any]] = Field(default_factory=list)
    anomalies: list[dict[str, Any]] = Field(default_factory=list)
    enforcements: list[dict[str, Any]] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)

    # Metrics
    anomaly_count: int = 0
    blocked_count: int = 0
    alert_count: int = 0

    # Metadata
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
