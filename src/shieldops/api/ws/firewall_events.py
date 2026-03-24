"""WebSocket event definitions for real-time firewall notifications."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- Event Types ---


class FirewallEventType(StrEnum):
    CALL_INTERCEPTED = "agent.firewall.call_intercepted"
    ANOMALY_DETECTED = "agent.firewall.anomaly_detected"
    POLICY_VIOLATED = "agent.firewall.policy_violated"
    CIRCUIT_BREAKER_TRIPPED = "agent.circuit_breaker.tripped"
    CIRCUIT_BREAKER_RESET = "agent.circuit_breaker.reset"
    KILL_SWITCH_ACTIVATED = "agent.kill_switch.activated"


# --- Event Models ---


class CallInterceptedEvent(BaseModel):
    """Emitted when the firewall intercepts a tool call."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    tool_name: str = ""
    decision: str = "allow"
    risk_score: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    latency_ms: float = 0.0
    timestamp: float = Field(default_factory=time.time)


class AnomalyDetectedEvent(BaseModel):
    """Emitted when the firewall detects a behavioral anomaly."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    anomaly_type: str = ""
    risk_score: float = 0.0
    baseline_deviation: float = 0.0
    escalation_level: str = "monitor"
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)


class PolicyViolatedEvent(BaseModel):
    """Emitted when an agent violates a firewall policy."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    policy_rule_id: str = ""
    violation_severity: float = 0.0
    tool_name: str = ""
    action_taken: str = "block"
    timestamp: float = Field(default_factory=time.time)


class CircuitBreakerEvent(BaseModel):
    """Emitted when a circuit breaker state changes (tripped or reset)."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    previous_state: str = "closed"
    new_state: str = "open"
    trip_reason: str = ""
    risk_score: float = 0.0
    revoked_tokens: int = 0
    revoked_sessions: int = 0
    timestamp: float = Field(default_factory=time.time)


class KillSwitchEvent(BaseModel):
    """Emitted when the kill switch is activated for an agent."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    trigger_source: str = ""
    risk_score: float = 0.0
    anomaly_count: int = 0
    escalation_level: str = "kill"
    revoked_tokens: int = 0
    revoked_sessions: int = 0
    timestamp: float = Field(default_factory=time.time)


# --- Formatter ---


_EVENT_MODELS: dict[FirewallEventType, type[BaseModel]] = {
    FirewallEventType.CALL_INTERCEPTED: CallInterceptedEvent,
    FirewallEventType.ANOMALY_DETECTED: AnomalyDetectedEvent,
    FirewallEventType.POLICY_VIOLATED: PolicyViolatedEvent,
    FirewallEventType.CIRCUIT_BREAKER_TRIPPED: CircuitBreakerEvent,
    FirewallEventType.CIRCUIT_BREAKER_RESET: CircuitBreakerEvent,
    FirewallEventType.KILL_SWITCH_ACTIVATED: KillSwitchEvent,
}


class FirewallWebSocketEvents:
    """Formats firewall events for WebSocket broadcast.

    Usage::

        ws_events = FirewallWebSocketEvents()
        msg = ws_events.format_event(
            FirewallEventType.CALL_INTERCEPTED,
            CallInterceptedEvent(agent_id="agent-1", tool_name="search", decision="allow"),
        )
        await websocket.send_json(msg)
    """

    @staticmethod
    def format_event(
        event_type: FirewallEventType | str,
        data: BaseModel | dict[str, Any],
    ) -> dict[str, Any]:
        """Format an event for WebSocket broadcast.

        Returns a JSON-serializable dict with envelope metadata.
        """
        event_type_str = event_type if isinstance(event_type, str) else event_type.value

        payload = data.model_dump() if isinstance(data, BaseModel) else dict(data)

        return {
            "type": event_type_str,
            "data": payload,
            "meta": {
                "version": "1.0",
                "source": "shieldops.firewall",
                "broadcast_at": time.time(),
            },
        }

    @staticmethod
    def supported_events() -> list[str]:
        """Return all supported event type strings."""
        return [e.value for e in FirewallEventType]

    @staticmethod
    def event_model(event_type: FirewallEventType) -> type[BaseModel]:
        """Return the Pydantic model class for a given event type."""
        return _EVENT_MODELS[event_type]
