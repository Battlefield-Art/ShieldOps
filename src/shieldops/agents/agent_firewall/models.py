"""Agent Behavioral Firewall — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MonitoringMode(StrEnum):
    AUDIT = "audit"
    ENFORCE = "enforce"


class CircuitBreakerStatus(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CallAction(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    FLAGGED = "flagged"


class InterceptedCall(BaseModel):
    """A single intercepted tool call from a monitored agent."""

    agent_id: str = ""
    tool_name: str = ""
    args_hash: str = ""
    timestamp: float = 0.0
    latency_ms: float = 0.0
    result_summary: str = ""
    risk_score: float = 0.0
    action_taken: CallAction = CallAction.ALLOWED


class BehavioralAnomaly(BaseModel):
    """An anomaly detected in agent behavior."""

    type: str = ""
    description: str = ""
    severity: str = "low"
    confidence: float = 0.0
    evidence: dict[str, Any] = Field(default_factory=dict)


class PolicyViolation(BaseModel):
    """A policy rule violation by a monitored agent."""

    rule_id: str = ""
    rule_description: str = ""
    severity: str = "medium"
    call_id: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentFirewallState(BaseModel):
    """Main state for the Agent Behavioral Firewall graph."""

    # Input
    monitored_agent_id: str = ""
    monitoring_mode: MonitoringMode = MonitoringMode.AUDIT
    policy_set: dict[str, Any] = Field(default_factory=dict)
    time_window_minutes: int = 60

    # Monitoring
    intercepted_calls: list[dict[str, Any]] = Field(default_factory=list)
    behavioral_profile: dict[str, Any] = Field(default_factory=dict)
    anomalies_detected: list[dict[str, Any]] = Field(default_factory=list)
    policy_violations: list[dict[str, Any]] = Field(default_factory=list)

    # Response
    blocked_calls: list[dict[str, Any]] = Field(default_factory=list)
    alerts_generated: list[dict[str, Any]] = Field(default_factory=list)
    circuit_breaker_status: CircuitBreakerStatus = CircuitBreakerStatus.CLOSED

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
