"""AgentEscalationEngine — manages escalation chains for AI agent governance decisions."""

from __future__ import annotations

import time
import uuid
from collections import Counter
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EscalationPriority(StrEnum):
    P0 = "p0"
    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"


class EscalationOutcome(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"
    DEFERRED = "deferred"
    AUTO_RESOLVED = "auto_resolved"


class EscalationChannel(StrEnum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"
    IN_APP = "in_app"


# --- Models ---


class EscalationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    reason: str = ""
    priority: EscalationPriority = EscalationPriority.P3
    channel: EscalationChannel = EscalationChannel.IN_APP
    outcome: EscalationOutcome = EscalationOutcome.DEFERRED
    responder: str = ""
    escalated_at: float = Field(default_factory=time.time)
    resolved_at: float = 0.0
    response_time_sec: float = 0.0
    context: dict[str, Any] = Field(default_factory=dict)
    created_at: float = Field(default_factory=time.time)


class EscalationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    total_escalations: int = 0
    priority_distribution: dict[str, int] = Field(default_factory=dict)
    outcome_distribution: dict[str, int] = Field(default_factory=dict)
    avg_response_time_sec: float = 0.0
    p95_response_time_sec: float = 0.0
    auto_resolve_rate: float = 0.0
    bottleneck_channels: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)


class EscalationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    unique_agents: int = 0
    avg_response_time_sec: float = 0.0
    priority_breakdown: dict[str, int] = Field(default_factory=dict)
    channel_breakdown: dict[str, int] = Field(default_factory=dict)
    outcome_breakdown: dict[str, int] = Field(default_factory=dict)
    bottleneck_summary: list[dict[str, Any]] = Field(default_factory=list)
    routing_suggestions: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


_PRIORITY_SLA_SECONDS: dict[str, float] = {
    EscalationPriority.P0: 300,  # 5 min
    EscalationPriority.P1: 900,  # 15 min
    EscalationPriority.P2: 3600,  # 1 hour
    EscalationPriority.P3: 14400,  # 4 hours
    EscalationPriority.P4: 86400,  # 24 hours
}


class AgentEscalationEngine:
    """Manages escalation chains for AI agent governance decisions."""

    def __init__(self, max_records: int = 10000) -> None:
        self._records: list[EscalationRecord] = []
        self._max = max_records
        logger.info("agent_escalation_engine.initialized", max_records=max_records)

    # -- core methods --

    def add_record(self, **kwargs: Any) -> EscalationRecord:
        """Add an escalation record."""
        rec = EscalationRecord(**kwargs)
        # Auto-compute response time if resolved
        if rec.resolved_at > 0 and rec.response_time_sec == 0.0:
            rec.response_time_sec = round(rec.resolved_at - rec.escalated_at, 2)
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.debug(
            "agent_escalation_engine.record_added",
            agent_id=rec.agent_id,
            priority=rec.priority,
            channel=rec.channel,
        )
        return rec

    def process(self, agent_id: str) -> EscalationAnalysis:
        """Analyze escalation patterns for a specific agent."""
        filtered = [r for r in self._records if r.agent_id == agent_id]
        if not filtered:
            return EscalationAnalysis(agent_id=agent_id)

        prio_dist: Counter[str] = Counter()
        outcome_dist: Counter[str] = Counter()
        response_times: list[float] = []
        auto_resolved = 0
        channel_times: dict[str, list[float]] = {}

        for r in filtered:
            prio_dist[r.priority.value] += 1
            outcome_dist[r.outcome.value] += 1
            if r.response_time_sec > 0:
                response_times.append(r.response_time_sec)
                channel_times.setdefault(r.channel.value, []).append(r.response_time_sec)
            if r.outcome == EscalationOutcome.AUTO_RESOLVED:
                auto_resolved += 1

        avg_rt = round(sum(response_times) / len(response_times), 2) if response_times else 0.0
        sorted_rt = sorted(response_times)
        p95_idx = int(len(sorted_rt) * 0.95) if sorted_rt else 0
        p95_rt = sorted_rt[min(p95_idx, len(sorted_rt) - 1)] if sorted_rt else 0.0
        auto_rate = round(auto_resolved / len(filtered), 3) if filtered else 0.0

        # Identify bottleneck channels (avg response > 2x overall avg)
        bottleneck_channels: list[str] = []
        if avg_rt > 0:
            for ch, times in channel_times.items():
                ch_avg = sum(times) / len(times)
                if ch_avg > avg_rt * 2:
                    bottleneck_channels.append(ch)

        recommendations: list[str] = []
        if auto_rate < 0.2:
            recommendations.append("Low auto-resolve rate — consider adding automation rules")
        if prio_dist.get(EscalationPriority.P0, 0) > len(filtered) * 0.3:
            recommendations.append("High P0 ratio — review priority classification criteria")
        if bottleneck_channels:
            recommendations.append(
                f"Channels {bottleneck_channels} are slow — consider routing changes"
            )

        return EscalationAnalysis(
            agent_id=agent_id,
            total_escalations=len(filtered),
            priority_distribution=dict(prio_dist),
            outcome_distribution=dict(outcome_dist),
            avg_response_time_sec=avg_rt,
            p95_response_time_sec=round(p95_rt, 2),
            auto_resolve_rate=auto_rate,
            bottleneck_channels=bottleneck_channels,
            recommendations=recommendations,
        )

    def generate_report(self) -> EscalationReport:
        """Generate a comprehensive escalation report."""
        if not self._records:
            return EscalationReport()

        prio_bk: Counter[str] = Counter()
        channel_bk: Counter[str] = Counter()
        outcome_bk: Counter[str] = Counter()
        response_times: list[float] = []

        for r in self._records:
            prio_bk[r.priority.value] += 1
            channel_bk[r.channel.value] += 1
            outcome_bk[r.outcome.value] += 1
            if r.response_time_sec > 0:
                response_times.append(r.response_time_sec)

        avg_rt = round(sum(response_times) / len(response_times), 2) if response_times else 0.0
        bottleneck_summary = self.identify_bottlenecks()
        routing = self.optimize_escalation_routing()

        return EscalationReport(
            total_records=len(self._records),
            unique_agents=len({r.agent_id for r in self._records}),
            avg_response_time_sec=avg_rt,
            priority_breakdown=dict(prio_bk),
            channel_breakdown=dict(channel_bk),
            outcome_breakdown=dict(outcome_bk),
            bottleneck_summary=bottleneck_summary,
            routing_suggestions=routing,
        )

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics."""
        resolved = [r for r in self._records if r.response_time_sec > 0]
        avg_rt = (
            round(sum(r.response_time_sec for r in resolved) / len(resolved), 2)
            if resolved
            else 0.0
        )
        return {
            "total_records": len(self._records),
            "unique_agents": len({r.agent_id for r in self._records}),
            "avg_response_time_sec": avg_rt,
            "pending": sum(1 for r in self._records if r.outcome == EscalationOutcome.DEFERRED),
        }

    def clear_data(self) -> None:
        """Clear all stored records."""
        self._records.clear()
        logger.info("agent_escalation_engine.cleared")

    # -- domain methods --

    def calculate_response_time(self, priority: EscalationPriority | None = None) -> dict[str, Any]:
        """Calculate response time metrics, optionally filtered by priority."""
        filtered = self._records
        if priority:
            filtered = [r for r in filtered if r.priority == priority]

        resolved = [r for r in filtered if r.response_time_sec > 0]
        if not resolved:
            return {"avg": 0.0, "p50": 0.0, "p95": 0.0, "sla_breach_count": 0}

        times = sorted(r.response_time_sec for r in resolved)
        avg_t = round(sum(times) / len(times), 2)
        p50 = times[len(times) // 2]
        p95 = times[int(len(times) * 0.95)]

        sla_breaches = 0
        for r in resolved:
            sla = _PRIORITY_SLA_SECONDS.get(r.priority, 86400)
            if r.response_time_sec > sla:
                sla_breaches += 1

        return {
            "avg": avg_t,
            "p50": round(p50, 2),
            "p95": round(p95, 2),
            "total_resolved": len(resolved),
            "sla_breach_count": sla_breaches,
            "sla_breach_rate": round(sla_breaches / len(resolved), 3),
        }

    def identify_bottlenecks(self) -> list[dict[str, Any]]:
        """Identify escalation bottlenecks by channel and priority."""
        channel_stats: dict[str, dict[str, Any]] = {}

        for r in self._records:
            key = f"{r.channel.value}:{r.priority.value}"
            if key not in channel_stats:
                channel_stats[key] = {
                    "channel": r.channel.value,
                    "priority": r.priority.value,
                    "count": 0,
                    "total_time": 0.0,
                    "pending": 0,
                }
            channel_stats[key]["count"] += 1
            if r.response_time_sec > 0:
                channel_stats[key]["total_time"] += r.response_time_sec
            if r.outcome == EscalationOutcome.DEFERRED:
                channel_stats[key]["pending"] += 1

        bottlenecks: list[dict[str, Any]] = []
        for _key, stats in channel_stats.items():
            resolved_count = stats["count"] - stats["pending"]
            avg_time = round(stats["total_time"] / resolved_count, 2) if resolved_count > 0 else 0.0
            sla = _PRIORITY_SLA_SECONDS.get(stats["priority"], 86400)
            is_bottleneck = avg_time > sla or stats["pending"] > stats["count"] * 0.5

            if is_bottleneck:
                bottlenecks.append(
                    {
                        "channel": stats["channel"],
                        "priority": stats["priority"],
                        "avg_response_sec": avg_time,
                        "sla_target_sec": sla,
                        "pending_count": stats["pending"],
                        "total_count": stats["count"],
                    }
                )

        return sorted(bottlenecks, key=lambda b: b.get("avg_response_sec", 0), reverse=True)

    def optimize_escalation_routing(self) -> list[str]:
        """Generate routing optimization suggestions based on historical patterns."""
        suggestions: list[str] = []
        if not self._records:
            return suggestions

        # Analyze channel effectiveness
        channel_outcomes: dict[str, Counter[str]] = {}
        for r in self._records:
            if r.channel.value not in channel_outcomes:
                channel_outcomes[r.channel.value] = Counter()
            channel_outcomes[r.channel.value][r.outcome.value] += 1

        for ch, outcomes in channel_outcomes.items():
            total = sum(outcomes.values())
            denied = outcomes.get(EscalationOutcome.DENIED, 0)
            deferred = outcomes.get(EscalationOutcome.DEFERRED, 0)
            if total > 0 and deferred / total > 0.5:
                suggestions.append(
                    f"Channel '{ch}' has {round(deferred / total * 100)}% deferred — "
                    f"consider re-routing to faster channel"
                )
            if total > 0 and denied / total > 0.4:
                suggestions.append(
                    f"Channel '{ch}' has high denial rate — review pre-escalation filtering"
                )

        # Check for P0/P1 going through slow channels
        high_prio_slow = [
            r
            for r in self._records
            if r.priority in (EscalationPriority.P0, EscalationPriority.P1)
            and r.channel == EscalationChannel.EMAIL
        ]
        if high_prio_slow:
            suggestions.append(
                f"{len(high_prio_slow)} high-priority escalations routed via email — "
                f"switch to PagerDuty or Slack"
            )

        # Auto-resolve candidates
        auto_resolvable = [
            r
            for r in self._records
            if r.priority in (EscalationPriority.P3, EscalationPriority.P4)
            and r.outcome == EscalationOutcome.APPROVED
        ]
        if len(auto_resolvable) > 10:
            suggestions.append(
                f"{len(auto_resolvable)} low-priority escalations were approved — "
                f"consider auto-approval rules"
            )

        return suggestions
