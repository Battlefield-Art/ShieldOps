"""Agent Behavioral Firewall — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CallAction,
    CircuitBreakerStatus,
    MonitoringMode,
)
from .tools import AgentFirewallToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def ingest_calls(state: dict[str, Any], toolkit: AgentFirewallToolkit) -> dict[str, Any]:
    """Ingest and record intercepted tool calls."""
    logger.info("agent_firewall.node.ingest_calls")
    state = _to_dict(state)
    agent_id = state.get("monitored_agent_id", "")
    raw_calls = state.get("intercepted_calls", [])
    session_start = time.time()

    processed: list[dict[str, Any]] = []
    for raw in raw_calls:
        call = await toolkit.intercept_call(
            agent_id=agent_id,
            tool_name=raw.get("tool_name", "unknown"),
            args=raw.get("args", {}),
            data_volume=raw.get("data_volume", 0),
        )
        processed.append(call.model_dump())

    return {
        "intercepted_calls": processed,
        "session_start": session_start,
        "current_step": "ingest_calls",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Ingested {len(processed)} tool calls for agent {agent_id}"],
    }


async def build_baseline(state: dict[str, Any], toolkit: AgentFirewallToolkit) -> dict[str, Any]:
    """Build behavioral baseline from call history."""
    logger.info("agent_firewall.node.build_baseline")
    state = _to_dict(state)
    agent_id = state.get("monitored_agent_id", "")
    window = state.get("time_window_minutes", 60)

    profile = await toolkit.build_behavioral_profile(
        agent_id=agent_id,
        window_minutes=window,
    )

    return {
        "behavioral_profile": profile,
        "current_step": "build_baseline",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Built behavioral profile: {profile.get('call_count', 0)} calls analyzed"],
    }


async def detect_anomalies(state: dict[str, Any], toolkit: AgentFirewallToolkit) -> dict[str, Any]:
    """Detect behavioral anomalies using baseline comparison and LLM analysis."""
    logger.info("agent_firewall.node.detect_anomalies")
    state = _to_dict(state)
    agent_id = state.get("monitored_agent_id", "")
    raw_calls = state.get("intercepted_calls", [])

    all_anomalies: list[dict[str, Any]] = []
    for call_data in raw_calls:
        tool_name = call_data.get("tool_name", "")
        data_volume = call_data.get("data_volume", 0)
        anomalies = await toolkit.evaluate_against_baseline(
            agent_id=agent_id,
            tool_name=tool_name,
            data_volume=data_volume,
        )
        all_anomalies.extend([a.model_dump() for a in anomalies])

    reasoning_note = f"Detected {len(all_anomalies)} anomalies across {len(raw_calls)} calls"

    # LLM enhancement: deeper anomaly analysis
    try:
        from .prompts import SYSTEM_BEHAVIORAL_ANALYSIS, AnomalyAnalysisResult

        analysis_context = json.dumps(
            {
                "agent_id": agent_id,
                "call_count": len(raw_calls),
                "anomaly_count": len(all_anomalies),
                "behavioral_profile": state.get("behavioral_profile", {}),
                "anomalies_summary": all_anomalies[:20],
            },
            default=str,
        )
        llm_result = cast(
            AnomalyAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_BEHAVIORAL_ANALYSIS,
                user_prompt=f"Agent behavioral data:\n{analysis_context}",
                schema=AnomalyAnalysisResult,
            ),
        )
        logger.info("llm_enhanced", agent="agent_firewall", node="detect_anomalies")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="agent_firewall", node="detect_anomalies")

    return {
        "anomalies_detected": all_anomalies,
        "current_step": "detect_anomalies",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def evaluate_policies(state: dict[str, Any], toolkit: AgentFirewallToolkit) -> dict[str, Any]:
    """Evaluate intercepted calls against firewall policies."""
    logger.info("agent_firewall.node.evaluate_policies")
    state = _to_dict(state)
    agent_id = state.get("monitored_agent_id", "")
    policy_set = state.get("policy_set", {})

    violations = await toolkit.check_data_access_patterns(
        agent_id=agent_id,
        policy_set=policy_set,
    )
    violation_dicts = [v.model_dump() for v in violations]

    return {
        "policy_violations": violation_dicts,
        "current_step": "evaluate_policies",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Evaluated policies: {len(violation_dicts)} violations found"],
    }


async def enforce_actions(state: dict[str, Any], toolkit: AgentFirewallToolkit) -> dict[str, Any]:
    """Enforce firewall actions based on violations and monitoring mode."""
    logger.info("agent_firewall.node.enforce_actions")
    state = _to_dict(state)
    agent_id = state.get("monitored_agent_id", "")
    mode = state.get("monitoring_mode", MonitoringMode.AUDIT.value)
    violations = state.get("policy_violations", [])
    anomalies = state.get("anomalies_detected", [])

    blocked: list[dict[str, Any]] = []
    cb_status = CircuitBreakerStatus.CLOSED

    # Count high-severity issues
    high_severity = sum(1 for v in violations if v.get("severity") in ("high", "critical")) + sum(
        1 for a in anomalies if a.get("severity") in ("high", "critical")
    )

    if mode == MonitoringMode.ENFORCE.value:
        # Block calls from violating agents
        for violation in violations:
            if violation.get("severity") in ("high", "critical"):
                blocked.append(
                    {
                        "call_id": violation.get("call_id", ""),
                        "rule_id": violation.get("rule_id", ""),
                        "reason": violation.get("rule_description", ""),
                        "action": CallAction.BLOCKED.value,
                        "timestamp": time.time(),
                    }
                )

        # Trigger circuit breaker on critical threshold
        if high_severity >= 3:
            await toolkit.trigger_circuit_breaker(
                agent_id=agent_id,
                status=CircuitBreakerStatus.OPEN,
            )
            cb_status = CircuitBreakerStatus.OPEN

    # LLM threat assessment
    reasoning_note = f"Enforcement: {len(blocked)} calls blocked, CB={cb_status.value}"
    try:
        from .prompts import SYSTEM_THREAT_ASSESSMENT, ThreatAssessmentResult

        threat_context = json.dumps(
            {
                "agent_id": agent_id,
                "violations": violations[:10],
                "anomalies": anomalies[:10],
                "high_severity_count": high_severity,
                "mode": mode,
            },
            default=str,
        )
        llm_result = cast(
            ThreatAssessmentResult,
            await llm_structured(
                system_prompt=SYSTEM_THREAT_ASSESSMENT,
                user_prompt=f"Threat assessment context:\n{threat_context}",
                schema=ThreatAssessmentResult,
            ),
        )
        logger.info("llm_enhanced", agent="agent_firewall", node="enforce_actions")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"

        if llm_result.kill_switch_recommended and mode == MonitoringMode.ENFORCE.value:
            await toolkit.trigger_circuit_breaker(
                agent_id=agent_id,
                status=CircuitBreakerStatus.OPEN,
            )
            cb_status = CircuitBreakerStatus.OPEN
    except Exception:
        logger.debug("llm_fallback", agent="agent_firewall", node="enforce_actions")

    return {
        "blocked_calls": blocked,
        "circuit_breaker_status": cb_status.value,
        "current_step": "enforce_actions",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_alerts(state: dict[str, Any], toolkit: AgentFirewallToolkit) -> dict[str, Any]:
    """Generate alerts for anomalies and violations."""
    logger.info("agent_firewall.node.generate_alerts")
    state = _to_dict(state)
    agent_id = state.get("monitored_agent_id", "")
    anomalies = state.get("anomalies_detected", [])
    violations = state.get("policy_violations", [])
    blocked = state.get("blocked_calls", [])

    alerts: list[dict[str, Any]] = []

    for anomaly in anomalies:
        if anomaly.get("severity") in ("high", "critical"):
            alerts.append(
                {
                    "type": "anomaly",
                    "agent_id": agent_id,
                    "severity": anomaly.get("severity", "medium"),
                    "description": anomaly.get("description", ""),
                    "timestamp": time.time(),
                }
            )

    for violation in violations:
        alerts.append(
            {
                "type": "policy_violation",
                "agent_id": agent_id,
                "severity": violation.get("severity", "medium"),
                "rule_id": violation.get("rule_id", ""),
                "description": violation.get("rule_description", ""),
                "timestamp": time.time(),
            }
        )

    if blocked:
        alerts.append(
            {
                "type": "enforcement",
                "agent_id": agent_id,
                "severity": "high",
                "description": f"{len(blocked)} calls blocked by firewall",
                "timestamp": time.time(),
            }
        )

    return {
        "alerts_generated": alerts,
        "current_step": "generate_alerts",
        "reasoning_chain": state.get("reasoning_chain", []) + [f"Generated {len(alerts)} alerts"],
    }


async def report(state: dict[str, Any], toolkit: AgentFirewallToolkit) -> dict[str, Any]:
    """Generate final firewall monitoring report."""
    logger.info("agent_firewall.node.report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    return {
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report complete: {len(state.get('intercepted_calls', []))} calls monitored, "
            f"{len(state.get('anomalies_detected', []))} anomalies, "
            f"{len(state.get('policy_violations', []))} violations, "
            f"{len(state.get('blocked_calls', []))} blocked"
        ],
    }
