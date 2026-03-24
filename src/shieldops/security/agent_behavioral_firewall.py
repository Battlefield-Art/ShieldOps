"""Agent Behavioral Firewall — runtime monitoring and control of AI agent tool calls."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MonitoringMode(StrEnum):
    AUDIT = "audit"
    ENFORCE = "enforce"
    LEARNING = "learning"
    DISABLED = "disabled"


class AnomalyType(StrEnum):
    RATE_SPIKE = "rate_spike"
    UNUSUAL_TOOL = "unusual_tool"
    DATA_VOLUME_SPIKE = "data_volume_spike"
    OFF_HOURS_ACCESS = "off_hours_access"
    SCOPE_VIOLATION = "scope_violation"
    SEQUENTIAL_ANOMALY = "sequential_anomaly"


class FirewallAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    FLAG = "flag"
    THROTTLE = "throttle"
    KILL_SWITCH = "kill_switch"


# --- Models ---


class FirewallEventRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    tool_name: str = ""
    action_taken: FirewallAction = FirewallAction.ALLOW
    risk_score: float = 0.0
    anomaly_type: str = ""
    policy_rule_id: str = ""
    timestamp: float = Field(default_factory=time.time)


class BehavioralProfile(BaseModel):
    agent_id: str = ""
    normal_tools: list[str] = Field(default_factory=list)
    normal_rate_per_minute: float = 0.0
    normal_hours: list[int] = Field(default_factory=lambda: list(range(8, 20)))
    normal_data_volume_per_call: float = 0.0
    baseline_window_hours: int = 24
    sample_count: int = 0
    last_updated: float = Field(default_factory=time.time)


class FirewallReport(BaseModel):
    total_events: int = 0
    total_profiles: int = 0
    blocked_count: int = 0
    flagged_count: int = 0
    by_action: dict[str, int] = Field(default_factory=dict)
    by_anomaly_type: dict[str, int] = Field(default_factory=dict)
    top_violating_agents: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentBehavioralFirewall:
    """Runtime monitoring and control of AI agent tool calls."""

    def __init__(
        self,
        max_records: int = 200000,
        default_rate_limit: float = 60.0,
        default_data_limit: float = 1_000_000.0,
    ) -> None:
        self._max_records = max_records
        self._default_rate_limit = default_rate_limit
        self._default_data_limit = default_data_limit
        self._records: list[FirewallEventRecord] = []
        self._profiles: dict[str, BehavioralProfile] = {}
        logger.info(
            "agent_behavioral_firewall.initialized",
            max_records=max_records,
            default_rate_limit=default_rate_limit,
        )

    # -- record / query --

    def record_event(
        self,
        agent_id: str,
        tool_name: str,
        action: FirewallAction = FirewallAction.ALLOW,
        risk_score: float = 0.0,
        anomaly_type: str = "",
        policy_rule_id: str = "",
    ) -> FirewallEventRecord:
        record = FirewallEventRecord(
            agent_id=agent_id,
            tool_name=tool_name,
            action_taken=action,
            risk_score=risk_score,
            anomaly_type=anomaly_type,
            policy_rule_id=policy_rule_id,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_behavioral_firewall.event_recorded",
            record_id=record.id,
            agent_id=agent_id,
            tool_name=tool_name,
            action=action.value,
        )
        return record

    def list_events(
        self,
        agent_id: str | None = None,
        action: FirewallAction | None = None,
        limit: int = 50,
    ) -> list[FirewallEventRecord]:
        results = list(self._records)
        if agent_id is not None:
            results = [r for r in results if r.agent_id == agent_id]
        if action is not None:
            results = [r for r in results if r.action_taken == action]
        return results[-limit:]

    # -- baseline --

    def build_baseline(
        self,
        agent_id: str,
        window_hours: int = 24,
    ) -> BehavioralProfile:
        """Compute behavioral profile from event history."""
        cutoff = time.time() - (window_hours * 3600)
        events = [r for r in self._records if r.agent_id == agent_id and r.timestamp >= cutoff]
        if not events:
            profile = BehavioralProfile(agent_id=agent_id, baseline_window_hours=window_hours)
            self._profiles[agent_id] = profile
            return profile

        tools = list({e.tool_name for e in events})
        duration_min = max((time.time() - events[0].timestamp) / 60, 1.0)
        rate = len(events) / duration_min
        hours = list({int(time.gmtime(e.timestamp).tm_hour) for e in events})

        profile = BehavioralProfile(
            agent_id=agent_id,
            normal_tools=tools,
            normal_rate_per_minute=round(rate, 2),
            normal_hours=sorted(hours),
            normal_data_volume_per_call=0.0,
            baseline_window_hours=window_hours,
            sample_count=len(events),
        )
        self._profiles[agent_id] = profile
        logger.info(
            "agent_behavioral_firewall.baseline_built",
            agent_id=agent_id,
            tools=len(tools),
            sample_count=len(events),
        )
        return profile

    # -- evaluation --

    def evaluate_call(
        self,
        agent_id: str,
        tool_name: str,
        args_summary: str = "",
        data_volume: float = 0.0,
    ) -> dict[str, Any]:
        """Evaluate a tool call against the baseline, returning action and risk."""
        profile = self._profiles.get(agent_id)
        risk = 0.0
        reasons: list[str] = []

        if not profile or profile.sample_count == 0:
            return {
                "action": FirewallAction.ALLOW.value,
                "risk_score": 0.1,
                "reasons": ["no_baseline"],
            }

        # Scope check
        if profile.normal_tools and tool_name not in profile.normal_tools:
            risk += 0.4
            reasons.append(f"unusual_tool:{tool_name}")

        # Rate check
        rate_result = self.detect_rate_anomaly(agent_id)
        if rate_result.get("anomaly"):
            risk += 0.3
            reasons.append("rate_spike")

        # Data volume check
        if data_volume > self._default_data_limit:
            risk += 0.3
            reasons.append("data_volume_spike")

        # Hours check
        current_hour = int(time.gmtime().tm_hour)
        if profile.normal_hours and current_hour not in profile.normal_hours:
            risk += 0.15
            reasons.append("off_hours_access")

        risk = min(risk, 1.0)
        if risk >= 0.9:
            action = FirewallAction.BLOCK
        elif risk >= 0.6:
            action = FirewallAction.FLAG
        elif risk >= 0.4:
            action = FirewallAction.THROTTLE
        else:
            action = FirewallAction.ALLOW

        return {
            "action": action.value,
            "risk_score": round(risk, 4),
            "reasons": reasons,
        }

    # -- domain methods --

    def detect_rate_anomaly(
        self,
        agent_id: str,
        window_minutes: int = 1,
    ) -> dict[str, Any]:
        """Check if current call rate exceeds the baseline."""
        cutoff = time.time() - (window_minutes * 60)
        recent = [r for r in self._records if r.agent_id == agent_id and r.timestamp >= cutoff]
        rate = len(recent) / max(window_minutes, 1)
        profile = self._profiles.get(agent_id)
        baseline_rate = profile.normal_rate_per_minute if profile else self._default_rate_limit
        anomaly = rate > max(baseline_rate * 2, self._default_rate_limit)
        return {
            "agent_id": agent_id,
            "current_rate": round(rate, 2),
            "baseline_rate": round(baseline_rate, 2),
            "anomaly": anomaly,
        }

    def detect_scope_violation(
        self,
        agent_id: str,
        tool_name: str,
        allowed_tools: list[str] | None = None,
    ) -> dict[str, Any]:
        """Check if agent is using unauthorized tools."""
        profile = self._profiles.get(agent_id)
        effective_allowed = allowed_tools or (profile.normal_tools if profile else [])
        violation = bool(effective_allowed and tool_name not in effective_allowed)
        return {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "allowed_tools": effective_allowed,
            "violation": violation,
        }

    def get_agent_risk_summary(self, agent_id: str) -> dict[str, Any]:
        """Summarize risk posture for a specific agent."""
        events = [r for r in self._records if r.agent_id == agent_id]
        if not events:
            return {"agent_id": agent_id, "status": "no_data"}
        blocked = sum(1 for e in events if e.action_taken == FirewallAction.BLOCK)
        flagged = sum(1 for e in events if e.action_taken == FirewallAction.FLAG)
        avg_risk = sum(e.risk_score for e in events) / len(events)
        return {
            "agent_id": agent_id,
            "total_events": len(events),
            "blocked": blocked,
            "flagged": flagged,
            "avg_risk_score": round(avg_risk, 4),
        }

    # -- report / stats --

    def generate_report(self) -> FirewallReport:
        by_action: dict[str, int] = {}
        by_anomaly: dict[str, int] = {}
        for r in self._records:
            by_action[r.action_taken.value] = by_action.get(r.action_taken.value, 0) + 1
            if r.anomaly_type:
                by_anomaly[r.anomaly_type] = by_anomaly.get(r.anomaly_type, 0) + 1

        blocked = sum(1 for r in self._records if r.action_taken == FirewallAction.BLOCK)
        flagged = sum(1 for r in self._records if r.action_taken == FirewallAction.FLAG)

        # Top violating agents
        agent_violations: dict[str, int] = {}
        for r in self._records:
            if r.action_taken in (FirewallAction.BLOCK, FirewallAction.FLAG):
                agent_violations[r.agent_id] = agent_violations.get(r.agent_id, 0) + 1
        top_agents = sorted(
            [{"agent_id": k, "violation_count": v} for k, v in agent_violations.items()],
            key=lambda x: x["violation_count"],
            reverse=True,
        )[:10]

        recs: list[str] = []
        if blocked > 0:
            recs.append(f"{blocked} calls blocked — review agent configurations")
        if flagged > 0:
            recs.append(f"{flagged} calls flagged — investigate anomalies")
        if not recs:
            recs.append("All agent tool calls within normal parameters")

        return FirewallReport(
            total_events=len(self._records),
            total_profiles=len(self._profiles),
            blocked_count=blocked,
            flagged_count=flagged,
            by_action=by_action,
            by_anomaly_type=by_anomaly,
            top_violating_agents=top_agents,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        action_dist: dict[str, int] = {}
        for r in self._records:
            key = r.action_taken.value
            action_dist[key] = action_dist.get(key, 0) + 1
        return {
            "total_events": len(self._records),
            "total_profiles": len(self._profiles),
            "action_distribution": action_dist,
            "unique_agents": len({r.agent_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._profiles.clear()
        logger.info("agent_behavioral_firewall.cleared")
        return {"status": "cleared"}
