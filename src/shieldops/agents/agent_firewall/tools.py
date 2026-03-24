"""Agent Behavioral Firewall — Tool functions for runtime agent monitoring."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import (
    BehavioralAnomaly,
    CallAction,
    CircuitBreakerStatus,
    InterceptedCall,
    PolicyViolation,
)

logger = structlog.get_logger()

# Default behavioral baseline thresholds
_DEFAULT_RATE_LIMIT = 60  # calls per minute
_DEFAULT_DATA_VOLUME_LIMIT = 1_000_000  # bytes per call
_ANOMALY_Z_THRESHOLD = 2.5


class AgentFirewallToolkit:
    """Tools for monitoring and controlling AI agent tool calls."""

    def __init__(
        self,
        policy_engine: Any | None = None,
        event_store: Any | None = None,
        alert_sink: Any | None = None,
    ) -> None:
        self._policy_engine = policy_engine
        self._event_store = event_store
        self._alert_sink = alert_sink
        self._call_history: dict[str, list[InterceptedCall]] = {}
        self._baselines: dict[str, dict[str, Any]] = {}
        self._circuit_breakers: dict[str, CircuitBreakerStatus] = {}

    async def intercept_call(
        self,
        agent_id: str,
        tool_name: str,
        args: dict[str, Any] | None = None,
        data_volume: int = 0,
    ) -> InterceptedCall:
        """Intercept and record a tool call from a monitored agent."""
        logger.info(
            "agent_firewall.intercept_call",
            agent_id=agent_id,
            tool_name=tool_name,
        )
        args = args or {}
        args_hash = hashlib.sha256(str(sorted(args.items())).encode()).hexdigest()[:16]
        start = time.time()

        # Check circuit breaker
        cb_status = self._circuit_breakers.get(agent_id, CircuitBreakerStatus.CLOSED)
        if cb_status == CircuitBreakerStatus.OPEN:
            call = InterceptedCall(
                agent_id=agent_id,
                tool_name=tool_name,
                args_hash=args_hash,
                timestamp=start,
                latency_ms=0.0,
                result_summary="blocked_by_circuit_breaker",
                risk_score=1.0,
                action_taken=CallAction.BLOCKED,
            )
            self._append_call(agent_id, call)
            return call

        # Evaluate risk
        risk_score = await self._compute_risk(agent_id, tool_name, data_volume)
        action = CallAction.ALLOWED
        if risk_score >= 0.9:
            action = CallAction.BLOCKED
        elif risk_score >= 0.6:
            action = CallAction.FLAGGED

        latency_ms = (time.time() - start) * 1000
        call = InterceptedCall(
            agent_id=agent_id,
            tool_name=tool_name,
            args_hash=args_hash,
            timestamp=start,
            latency_ms=round(latency_ms, 2),
            result_summary=f"risk={risk_score:.2f}",
            risk_score=round(risk_score, 4),
            action_taken=action,
        )
        self._append_call(agent_id, call)
        return call

    async def build_behavioral_profile(
        self,
        agent_id: str,
        window_minutes: int = 60,
    ) -> dict[str, Any]:
        """Build a behavioral profile from recent call history."""
        logger.info(
            "agent_firewall.build_profile",
            agent_id=agent_id,
            window_minutes=window_minutes,
        )
        calls = self._call_history.get(agent_id, [])
        cutoff = time.time() - (window_minutes * 60)
        recent = [c for c in calls if c.timestamp >= cutoff]

        if not recent:
            return {"agent_id": agent_id, "status": "no_data", "call_count": 0}

        tools_used = list({c.tool_name for c in recent})
        avg_risk = sum(c.risk_score for c in recent) / len(recent)
        call_rate = len(recent) / max(window_minutes, 1)
        avg_latency = sum(c.latency_ms for c in recent) / len(recent)

        profile = {
            "agent_id": agent_id,
            "call_count": len(recent),
            "tools_used": tools_used,
            "tool_diversity": len(tools_used),
            "avg_risk_score": round(avg_risk, 4),
            "calls_per_minute": round(call_rate, 2),
            "avg_latency_ms": round(avg_latency, 2),
            "blocked_count": sum(1 for c in recent if c.action_taken == CallAction.BLOCKED),
            "flagged_count": sum(1 for c in recent if c.action_taken == CallAction.FLAGGED),
            "window_minutes": window_minutes,
        }
        self._baselines[agent_id] = profile
        return profile

    async def evaluate_against_baseline(
        self,
        agent_id: str,
        tool_name: str,
        data_volume: int = 0,
    ) -> list[BehavioralAnomaly]:
        """Compare current call against the established baseline."""
        logger.info(
            "agent_firewall.evaluate_baseline",
            agent_id=agent_id,
            tool_name=tool_name,
        )
        baseline = self._baselines.get(agent_id)
        anomalies: list[BehavioralAnomaly] = []

        if not baseline:
            return anomalies

        # Unusual tool check
        known_tools = baseline.get("tools_used", [])
        if tool_name not in known_tools:
            anomalies.append(
                BehavioralAnomaly(
                    type="unusual_tool",
                    description=f"Agent {agent_id} using unknown tool: {tool_name}",
                    severity="high",
                    confidence=0.85,
                    evidence={"tool_name": tool_name, "known_tools": known_tools},
                )
            )

        # Rate spike check
        current_rate = baseline.get("calls_per_minute", 0)
        if current_rate > _DEFAULT_RATE_LIMIT:
            anomalies.append(
                BehavioralAnomaly(
                    type="rate_spike",
                    description=f"Call rate {current_rate}/min exceeds limit {_DEFAULT_RATE_LIMIT}",
                    severity="medium",
                    confidence=0.9,
                    evidence={"current_rate": current_rate, "limit": _DEFAULT_RATE_LIMIT},
                )
            )

        # Data volume check
        if data_volume > _DEFAULT_DATA_VOLUME_LIMIT:
            anomalies.append(
                BehavioralAnomaly(
                    type="data_volume_spike",
                    description=f"Data volume {data_volume} exceeds limit",
                    severity="high",
                    confidence=0.8,
                    evidence={"data_volume": data_volume, "limit": _DEFAULT_DATA_VOLUME_LIMIT},
                )
            )

        return anomalies

    async def check_rate_limits(
        self,
        agent_id: str,
        window_minutes: int = 1,
    ) -> dict[str, Any]:
        """Check if agent is within rate limits."""
        calls = self._call_history.get(agent_id, [])
        cutoff = time.time() - (window_minutes * 60)
        recent = [c for c in calls if c.timestamp >= cutoff]
        rate = len(recent) / max(window_minutes, 1)
        exceeded = rate > _DEFAULT_RATE_LIMIT
        return {
            "agent_id": agent_id,
            "calls_in_window": len(recent),
            "rate_per_minute": round(rate, 2),
            "limit": _DEFAULT_RATE_LIMIT,
            "exceeded": exceeded,
        }

    async def check_data_access_patterns(
        self,
        agent_id: str,
        policy_set: dict[str, Any] | None = None,
    ) -> list[PolicyViolation]:
        """Check agent data access patterns against policies."""
        logger.info("agent_firewall.check_data_access", agent_id=agent_id)
        calls = self._call_history.get(agent_id, [])
        policy_set = policy_set or {}
        allowed_tools: list[str] = policy_set.get("allowed_tools", [])
        violations: list[PolicyViolation] = []

        for call in calls:
            if allowed_tools and call.tool_name not in allowed_tools:
                violations.append(
                    PolicyViolation(
                        rule_id="scope_violation",
                        rule_description=(
                            f"Tool {call.tool_name} not in allowed set for agent {agent_id}"
                        ),
                        severity="high",
                        call_id=call.args_hash,
                    )
                )

        max_rate = policy_set.get("max_calls_per_minute", _DEFAULT_RATE_LIMIT)
        rate_info = await self.check_rate_limits(agent_id)
        if rate_info["rate_per_minute"] > max_rate:
            violations.append(
                PolicyViolation(
                    rule_id="rate_limit_exceeded",
                    rule_description=(
                        f"Rate {rate_info['rate_per_minute']}/min exceeds policy {max_rate}/min"
                    ),
                    severity="medium",
                    call_id="aggregate",
                )
            )
        return violations

    async def trigger_circuit_breaker(
        self,
        agent_id: str,
        status: CircuitBreakerStatus = CircuitBreakerStatus.OPEN,
    ) -> dict[str, Any]:
        """Trigger the circuit breaker for a monitored agent."""
        logger.warning(
            "agent_firewall.circuit_breaker",
            agent_id=agent_id,
            status=status.value,
        )
        self._circuit_breakers[agent_id] = status
        return {
            "agent_id": agent_id,
            "circuit_breaker_status": status.value,
            "timestamp": time.time(),
        }

    # -- internal helpers --

    def _append_call(self, agent_id: str, call: InterceptedCall) -> None:
        if agent_id not in self._call_history:
            self._call_history[agent_id] = []
        self._call_history[agent_id].append(call)
        # Ring buffer per agent
        if len(self._call_history[agent_id]) > 10000:
            self._call_history[agent_id] = self._call_history[agent_id][-10000:]

    async def _compute_risk(
        self,
        agent_id: str,
        tool_name: str,
        data_volume: int,
    ) -> float:
        """Compute risk score for a tool call."""
        risk = 0.0
        baseline = self._baselines.get(agent_id)
        if baseline:
            known_tools = baseline.get("tools_used", [])
            if tool_name not in known_tools:
                risk += 0.4
            if data_volume > _DEFAULT_DATA_VOLUME_LIMIT:
                risk += 0.3
            rate_info = await self.check_rate_limits(agent_id)
            if rate_info["exceeded"]:
                risk += 0.3
        else:
            risk = 0.1  # No baseline = low default risk
        return min(risk, 1.0)
