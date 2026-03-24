"""Agent Tool Call Interceptor — pre/post-execution interception for AI agent tool calls."""

from __future__ import annotations

import fnmatch
import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class InterceptionPoint(StrEnum):
    PRE_EXECUTION = "pre_execution"
    POST_EXECUTION = "post_execution"
    ON_ERROR = "on_error"


class CallDecision(StrEnum):
    PROCEED = "proceed"
    BLOCK = "block"
    MODIFY = "modify"
    DELAY = "delay"


class RiskLevel(StrEnum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --- Models ---


class ToolCallRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    call_id: str = ""
    agent_id: str = ""
    tool_name: str = ""
    input_hash: str = ""
    output_summary: str = ""
    risk_level: RiskLevel = RiskLevel.SAFE
    decision: CallDecision = CallDecision.PROCEED
    latency_ms: float = 0.0
    timestamp: float = Field(default_factory=time.time)


class InterceptionPolicy(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_pattern: str = "*"
    max_calls_per_minute: float = 60.0
    max_data_bytes: int = 1_000_000
    required_approval: bool = False
    allowed_hours: list[int] = Field(default_factory=lambda: list(range(0, 24)))
    enabled: bool = True


class InterceptionReport(BaseModel):
    total_records: int = 0
    total_policies: int = 0
    blocked_count: int = 0
    by_decision: dict[str, int] = Field(default_factory=dict)
    by_risk_level: dict[str, int] = Field(default_factory=dict)
    per_agent_summary: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentToolCallInterceptor:
    """Pre/post-execution interception for AI agent tool calls."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[ToolCallRecord] = []
        self._policies: list[InterceptionPolicy] = []
        logger.info("agent_tool_call_interceptor.initialized", max_records=max_records)

    # -- core interception --

    def intercept(
        self,
        agent_id: str,
        tool_name: str,
        args: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Core interception entry point. Evaluate a tool call against all policies."""
        args = args or {}
        context = context or {}
        data_bytes = context.get("data_bytes", 0)
        reasons: list[str] = []
        risk = RiskLevel.SAFE
        decision = CallDecision.PROCEED

        matching_policies = self._match_policies(tool_name)

        for policy in matching_policies:
            # Rate limit check
            if not self._check_rate_ok(agent_id, tool_name, policy.max_calls_per_minute):
                reasons.append(f"rate_limit_exceeded:{policy.max_calls_per_minute}/min")
                risk = self._escalate_risk(risk, RiskLevel.HIGH)
                decision = CallDecision.BLOCK

            # Data size check
            if data_bytes > policy.max_data_bytes:
                reasons.append(f"data_exceeds:{data_bytes}>{policy.max_data_bytes}")
                risk = self._escalate_risk(risk, RiskLevel.MEDIUM)
                if decision == CallDecision.PROCEED:
                    decision = CallDecision.BLOCK

            # Hours check
            current_hour = int(time.gmtime().tm_hour)
            if current_hour not in policy.allowed_hours:
                reasons.append(f"outside_allowed_hours:{current_hour}")
                risk = self._escalate_risk(risk, RiskLevel.MEDIUM)
                if decision == CallDecision.PROCEED:
                    decision = CallDecision.DELAY

            # Approval check
            if policy.required_approval:
                reasons.append("requires_approval")
                risk = self._escalate_risk(risk, RiskLevel.LOW)
                if decision == CallDecision.PROCEED:
                    decision = CallDecision.DELAY

        if not reasons:
            reasons.append("all_policies_passed")

        return {
            "decision": decision.value,
            "risk_level": risk.value,
            "reasons": reasons,
            "matching_policies": len(matching_policies),
        }

    def record_call(
        self,
        agent_id: str,
        tool_name: str,
        decision: CallDecision = CallDecision.PROCEED,
        risk_level: RiskLevel = RiskLevel.SAFE,
        latency_ms: float = 0.0,
        input_hash: str = "",
        output_summary: str = "",
    ) -> ToolCallRecord:
        """Record a tool call in the audit log."""
        record = ToolCallRecord(
            call_id=str(uuid.uuid4())[:12],
            agent_id=agent_id,
            tool_name=tool_name,
            input_hash=input_hash,
            output_summary=output_summary,
            risk_level=risk_level,
            decision=decision,
            latency_ms=latency_ms,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_tool_call_interceptor.call_recorded",
            record_id=record.id,
            agent_id=agent_id,
            tool_name=tool_name,
            decision=decision.value,
        )
        return record

    # -- policy management --

    def add_policy(
        self,
        tool_pattern: str = "*",
        max_rate: float = 60.0,
        max_data: int = 1_000_000,
        required_approval: bool = False,
        allowed_hours: list[int] | None = None,
    ) -> InterceptionPolicy:
        """Add an interception policy."""
        policy = InterceptionPolicy(
            tool_pattern=tool_pattern,
            max_calls_per_minute=max_rate,
            max_data_bytes=max_data,
            required_approval=required_approval,
            allowed_hours=allowed_hours or list(range(0, 24)),
        )
        self._policies.append(policy)
        logger.info(
            "agent_tool_call_interceptor.policy_added",
            policy_id=policy.id,
            tool_pattern=tool_pattern,
        )
        return policy

    def list_policies(self) -> list[InterceptionPolicy]:
        return list(self._policies)

    def check_rate_limit(self, agent_id: str, tool_name: str) -> bool:
        """Check if agent is within rate limits for the given tool."""
        matching = self._match_policies(tool_name)
        if not matching:
            return True
        min_rate = min(p.max_calls_per_minute for p in matching)
        return self._check_rate_ok(agent_id, tool_name, min_rate)

    # -- reporting --

    def generate_audit_report(self, agent_id: str) -> dict[str, Any]:
        """Per-agent audit report — the shareable artifact."""
        events = [r for r in self._records if r.agent_id == agent_id]
        if not events:
            return {"agent_id": agent_id, "status": "no_data"}
        blocked = sum(1 for e in events if e.decision == CallDecision.BLOCK)
        by_tool: dict[str, int] = {}
        for e in events:
            by_tool[e.tool_name] = by_tool.get(e.tool_name, 0) + 1
        return {
            "agent_id": agent_id,
            "total_calls": len(events),
            "blocked_calls": blocked,
            "unique_tools": len(by_tool),
            "tool_breakdown": by_tool,
            "first_seen": events[0].timestamp,
            "last_seen": events[-1].timestamp,
        }

    def generate_report(self) -> InterceptionReport:
        by_decision: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        for r in self._records:
            by_decision[r.decision.value] = by_decision.get(r.decision.value, 0) + 1
            by_risk[r.risk_level.value] = by_risk.get(r.risk_level.value, 0) + 1

        blocked = sum(1 for r in self._records if r.decision == CallDecision.BLOCK)

        agent_ids = {r.agent_id for r in self._records}
        per_agent = []
        for aid in list(agent_ids)[:10]:
            agent_events = [r for r in self._records if r.agent_id == aid]
            per_agent.append(
                {
                    "agent_id": aid,
                    "call_count": len(agent_events),
                    "blocked": sum(1 for e in agent_events if e.decision == CallDecision.BLOCK),
                }
            )

        recs: list[str] = []
        if blocked > 0:
            recs.append(f"{blocked} calls blocked — review interception policies")
        if not recs:
            recs.append("All intercepted calls within policy bounds")

        return InterceptionReport(
            total_records=len(self._records),
            total_policies=len(self._policies),
            blocked_count=blocked,
            by_decision=by_decision,
            by_risk_level=by_risk,
            per_agent_summary=per_agent,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        decision_dist: dict[str, int] = {}
        for r in self._records:
            key = r.decision.value
            decision_dist[key] = decision_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_policies": len(self._policies),
            "decision_distribution": decision_dist,
            "unique_agents": len({r.agent_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._policies.clear()
        logger.info("agent_tool_call_interceptor.cleared")
        return {"status": "cleared"}

    # -- internal helpers --

    def _match_policies(self, tool_name: str) -> list[InterceptionPolicy]:
        return [
            p for p in self._policies if p.enabled and fnmatch.fnmatch(tool_name, p.tool_pattern)
        ]

    def _check_rate_ok(self, agent_id: str, tool_name: str, max_rate: float) -> bool:
        cutoff = time.time() - 60
        recent = [
            r
            for r in self._records
            if r.agent_id == agent_id and r.tool_name == tool_name and r.timestamp >= cutoff
        ]
        return len(recent) <= max_rate

    @staticmethod
    def _escalate_risk(current: RiskLevel, new: RiskLevel) -> RiskLevel:
        order = [
            RiskLevel.SAFE,
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        ]
        ci = order.index(current)
        ni = order.index(new)
        return order[max(ci, ni)]
