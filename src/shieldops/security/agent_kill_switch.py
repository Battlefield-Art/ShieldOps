"""Agent Kill Switch / Circuit Breaker — emergency brake for AI agents."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class TripReason(StrEnum):
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    POLICY_VIOLATION = "policy_violation"
    MANUAL_TRIGGER = "manual_trigger"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    DATA_EXFILTRATION = "data_exfiltration"
    PROMPT_INJECTION = "prompt_injection"


class RecoveryAction(StrEnum):
    AUTO_RESET = "auto_reset"
    MANUAL_RESET = "manual_reset"
    GRADUAL_RESTORE = "gradual_restore"
    PERMANENT_DISABLE = "permanent_disable"


# --- Models ---


class KillSwitchEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    previous_state: CircuitState = CircuitState.CLOSED
    new_state: CircuitState = CircuitState.CLOSED
    trip_reason: TripReason = TripReason.MANUAL_TRIGGER
    triggered_by: str = ""
    risk_score: float = 0.0
    revoked_tokens: int = 0
    revoked_sessions: int = 0
    timestamp: float = Field(default_factory=time.time)


class CircuitBreakerConfig(BaseModel):
    agent_id: str = ""
    auto_trip_threshold: float = 0.85
    cooldown_seconds: int = 300
    max_half_open_calls: int = 5
    auto_reset_enabled: bool = False
    notification_channels: list[str] = Field(default_factory=list)


class KillSwitchReport(BaseModel):
    total_events: int = 0
    agents_currently_open: int = 0
    agents_currently_half_open: int = 0
    avg_recovery_time_seconds: float = 0.0
    by_reason: dict[str, int] = Field(default_factory=dict)
    by_agent: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentKillSwitch:
    """Emergency circuit breaker for AI agents."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._events: list[KillSwitchEvent] = []
        self._configs: dict[str, CircuitBreakerConfig] = {}
        self._states: dict[str, CircuitState] = {}
        self._half_open_calls: dict[str, int] = {}
        self._trip_times: dict[str, float] = {}
        logger.info("agent_kill_switch.initialized", max_records=max_records)

    # -- core operations -------------------------------------------------

    def trip(
        self,
        agent_id: str,
        reason: TripReason = TripReason.MANUAL_TRIGGER,
        triggered_by: str = "system",
        risk_score: float = 1.0,
    ) -> KillSwitchEvent:
        """Trip the circuit breaker — transition agent to OPEN state."""
        previous = self._states.get(agent_id, CircuitState.CLOSED)
        revoked_tokens = max(1, int(risk_score * 10))
        revoked_sessions = max(1, int(risk_score * 5))
        event = KillSwitchEvent(
            agent_id=agent_id,
            previous_state=previous,
            new_state=CircuitState.OPEN,
            trip_reason=reason,
            triggered_by=triggered_by,
            risk_score=risk_score,
            revoked_tokens=revoked_tokens,
            revoked_sessions=revoked_sessions,
        )
        self._states[agent_id] = CircuitState.OPEN
        self._half_open_calls[agent_id] = 0
        self._trip_times[agent_id] = time.time()
        self._events.append(event)
        if len(self._events) > self._max_records:
            self._events = self._events[-self._max_records :]
        logger.info(
            "agent_kill_switch.tripped",
            agent_id=agent_id,
            reason=reason.value,
            risk_score=risk_score,
            revoked_tokens=revoked_tokens,
            revoked_sessions=revoked_sessions,
        )
        return event

    def reset(
        self,
        agent_id: str,
        triggered_by: str = "system",
    ) -> KillSwitchEvent:
        """Reset circuit: OPEN→HALF_OPEN or HALF_OPEN→CLOSED."""
        previous = self._states.get(agent_id, CircuitState.CLOSED)
        if previous == CircuitState.OPEN:
            new_state = CircuitState.HALF_OPEN
            self._half_open_calls[agent_id] = 0
        else:
            new_state = CircuitState.CLOSED
            self._half_open_calls.pop(agent_id, None)
            self._trip_times.pop(agent_id, None)
        event = KillSwitchEvent(
            agent_id=agent_id,
            previous_state=previous,
            new_state=new_state,
            trip_reason=TripReason.MANUAL_TRIGGER,
            triggered_by=triggered_by,
            risk_score=0.0,
        )
        self._states[agent_id] = new_state
        self._events.append(event)
        if len(self._events) > self._max_records:
            self._events = self._events[-self._max_records :]
        logger.info(
            "agent_kill_switch.reset",
            agent_id=agent_id,
            previous=previous.value,
            new_state=new_state.value,
        )
        return event

    def get_state(self, agent_id: str) -> CircuitState:
        """Get current circuit state for an agent."""
        return self._states.get(agent_id, CircuitState.CLOSED)

    def configure(self, agent_id: str, config: CircuitBreakerConfig) -> None:
        """Set circuit breaker configuration for an agent."""
        self._configs[agent_id] = config
        logger.info(
            "agent_kill_switch.configured",
            agent_id=agent_id,
            threshold=config.auto_trip_threshold,
        )

    # -- domain operations -----------------------------------------------

    def check_auto_trip(self, agent_id: str, current_risk_score: float) -> bool:
        """Auto-trip if risk exceeds configured threshold."""
        config = self._configs.get(agent_id)
        threshold = config.auto_trip_threshold if config else 0.85
        if current_risk_score >= threshold:
            state = self._states.get(agent_id, CircuitState.CLOSED)
            if state == CircuitState.CLOSED:
                self.trip(
                    agent_id,
                    reason=TripReason.BEHAVIORAL_ANOMALY,
                    triggered_by="auto_trip",
                    risk_score=current_risk_score,
                )
                return True
        return False

    def attempt_recovery(self, agent_id: str) -> dict[str, Any]:
        """Test if agent is safe to restore from HALF_OPEN to CLOSED."""
        state = self._states.get(agent_id, CircuitState.CLOSED)
        if state != CircuitState.HALF_OPEN:
            return {"agent_id": agent_id, "recovery": False, "reason": f"state is {state.value}"}
        config = self._configs.get(agent_id)
        max_calls = config.max_half_open_calls if config else 5
        current = self._half_open_calls.get(agent_id, 0) + 1
        self._half_open_calls[agent_id] = current
        if current >= max_calls:
            self.reset(agent_id, triggered_by="auto_recovery")
            return {
                "agent_id": agent_id,
                "recovery": True,
                "calls_completed": current,
                "new_state": CircuitState.CLOSED.value,
            }
        return {
            "agent_id": agent_id,
            "recovery": False,
            "calls_completed": current,
            "calls_required": max_calls,
        }

    def list_open_circuits(self) -> list[dict[str, Any]]:
        """List agents in OPEN or HALF_OPEN state."""
        results: list[dict[str, Any]] = []
        for agent_id, state in self._states.items():
            if state in (CircuitState.OPEN, CircuitState.HALF_OPEN):
                trip_time = self._trip_times.get(agent_id, 0.0)
                duration = time.time() - trip_time if trip_time else 0.0
                results.append(
                    {
                        "agent_id": agent_id,
                        "state": state.value,
                        "open_duration_seconds": round(duration, 2),
                    }
                )
        results.sort(key=lambda x: x["open_duration_seconds"], reverse=True)
        return results

    # -- report / stats --------------------------------------------------

    def generate_kill_switch_report(self) -> KillSwitchReport:
        by_reason: dict[str, int] = {}
        by_agent: dict[str, int] = {}
        for e in self._events:
            by_reason[e.trip_reason.value] = by_reason.get(e.trip_reason.value, 0) + 1
            by_agent[e.agent_id] = by_agent.get(e.agent_id, 0) + 1
        open_count = sum(1 for s in self._states.values() if s == CircuitState.OPEN)
        half_open_count = sum(1 for s in self._states.values() if s == CircuitState.HALF_OPEN)
        recovery_times: list[float] = []
        agent_trips: dict[str, float] = {}
        for e in self._events:
            if e.new_state == CircuitState.OPEN:
                agent_trips[e.agent_id] = e.timestamp
            elif e.new_state == CircuitState.CLOSED and e.agent_id in agent_trips:
                recovery_times.append(e.timestamp - agent_trips.pop(e.agent_id))
        avg_recovery = (
            round(sum(recovery_times) / len(recovery_times), 2) if recovery_times else 0.0
        )
        recs: list[str] = []
        if open_count > 0:
            recs.append(f"{open_count} agent(s) currently in OPEN state — review and recover")
        if by_reason.get("prompt_injection", 0) > 0:
            recs.append("Prompt injection trips detected — audit agent input pipelines")
        if by_reason.get("data_exfiltration", 0) > 0:
            recs.append("Data exfiltration trips detected — review DLP controls")
        if not recs:
            recs.append("All circuits healthy — no active trips")
        return KillSwitchReport(
            total_events=len(self._events),
            agents_currently_open=open_count,
            agents_currently_half_open=half_open_count,
            avg_recovery_time_seconds=avg_recovery,
            by_reason=by_reason,
            by_agent=by_agent,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        state_dist: dict[str, int] = {}
        for s in self._states.values():
            state_dist[s.value] = state_dist.get(s.value, 0) + 1
        return {
            "total_events": len(self._events),
            "total_configured_agents": len(self._configs),
            "state_distribution": state_dist,
            "unique_agents": len({e.agent_id for e in self._events}),
        }

    def clear_data(self) -> dict[str, str]:
        self._events.clear()
        self._configs.clear()
        self._states.clear()
        self._half_open_calls.clear()
        self._trip_times.clear()
        logger.info("agent_kill_switch.cleared")
        return {"status": "cleared"}
