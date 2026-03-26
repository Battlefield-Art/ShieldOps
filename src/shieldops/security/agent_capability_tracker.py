"""AgentCapabilityTracker — tracks AI agent capability registrations and boundary violations."""

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


class CapabilityScope(StrEnum):
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"
    ADMIN = "admin"
    UNRESTRICTED = "unrestricted"


class BoundaryStatus(StrEnum):
    WITHIN = "within"
    NEAR_LIMIT = "near_limit"
    EXCEEDED = "exceeded"
    BLOCKED = "blocked"


class GovernanceAction(StrEnum):
    APPROVE = "approve"
    RESTRICT = "restrict"
    REVOKE = "revoke"
    AUDIT = "audit"


# --- Models ---


class CapabilityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    capability: str = ""
    scope: CapabilityScope = CapabilityScope.READ_ONLY
    boundary_status: BoundaryStatus = BoundaryStatus.WITHIN
    governance_action: GovernanceAction = GovernanceAction.APPROVE
    resource_target: str = ""
    invocation_count: int = 0
    max_invocations: int = 1000
    risk_score: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: float = Field(default_factory=time.time)


class CapabilityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    total_capabilities: int = 0
    scope_distribution: dict[str, int] = Field(default_factory=dict)
    boundary_violations: int = 0
    blocked_actions: int = 0
    avg_risk_score: float = 0.0
    governance_summary: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)


class CapabilityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    unique_agents: int = 0
    total_violations: int = 0
    scope_breakdown: dict[str, int] = Field(default_factory=dict)
    boundary_breakdown: dict[str, int] = Field(default_factory=dict)
    high_risk_agents: list[str] = Field(default_factory=list)
    capability_matrix: dict[str, list[str]] = Field(default_factory=dict)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


_SCOPE_RISK_WEIGHTS: dict[str, float] = {
    CapabilityScope.READ_ONLY: 0.1,
    CapabilityScope.READ_WRITE: 0.4,
    CapabilityScope.ADMIN: 0.7,
    CapabilityScope.UNRESTRICTED: 1.0,
}

_BOUNDARY_NEAR_THRESHOLD = 0.8


class AgentCapabilityTracker:
    """Tracks AI agent capability registrations and boundary violations."""

    def __init__(self, max_records: int = 10000) -> None:
        self._records: list[CapabilityRecord] = []
        self._max = max_records
        logger.info("agent_capability_tracker.initialized", max_records=max_records)

    # -- core methods --

    def add_record(self, **kwargs: Any) -> CapabilityRecord:
        """Register a capability record for an agent."""
        rec = CapabilityRecord(**kwargs)
        # Auto-compute boundary status from invocation counts
        if rec.max_invocations > 0:
            ratio = rec.invocation_count / rec.max_invocations
            if ratio >= 1.0:
                rec.boundary_status = BoundaryStatus.EXCEEDED
            elif ratio >= _BOUNDARY_NEAR_THRESHOLD:
                rec.boundary_status = BoundaryStatus.NEAR_LIMIT
        # Auto-compute risk score from scope weight
        if rec.risk_score == 0.0:
            base = _SCOPE_RISK_WEIGHTS.get(rec.scope, 0.1)
            violation_mult = 1.5 if rec.boundary_status == BoundaryStatus.EXCEEDED else 1.0
            rec.risk_score = round(min(base * violation_mult, 1.0), 3)
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.debug(
            "agent_capability_tracker.record_added",
            agent_id=rec.agent_id,
            capability=rec.capability,
            scope=rec.scope,
        )
        return rec

    def process(self, agent_id: str) -> CapabilityAnalysis:
        """Analyze capabilities for a specific agent."""
        filtered = [r for r in self._records if r.agent_id == agent_id]
        if not filtered:
            return CapabilityAnalysis(agent_id=agent_id)

        scope_dist: Counter[str] = Counter()
        gov_summary: Counter[str] = Counter()
        violations = 0
        blocked = 0
        total_risk = 0.0

        for r in filtered:
            scope_dist[r.scope.value] += 1
            gov_summary[r.governance_action.value] += 1
            if r.boundary_status in (BoundaryStatus.EXCEEDED, BoundaryStatus.BLOCKED):
                violations += 1
            if r.boundary_status == BoundaryStatus.BLOCKED:
                blocked += 1
            total_risk += r.risk_score

        avg_risk = round(total_risk / len(filtered), 3) if filtered else 0.0
        recommendations: list[str] = []
        if violations > 0:
            recommendations.append(
                f"Agent {agent_id} has {violations} boundary violations — review scope grants"
            )
        if scope_dist.get(CapabilityScope.UNRESTRICTED, 0) > 0:
            recommendations.append(
                f"Agent {agent_id} has unrestricted capabilities — apply least-privilege"
            )
        if avg_risk > 0.6:
            recommendations.append(f"Agent {agent_id} risk score {avg_risk} exceeds threshold")

        return CapabilityAnalysis(
            agent_id=agent_id,
            total_capabilities=len(filtered),
            scope_distribution=dict(scope_dist),
            boundary_violations=violations,
            blocked_actions=blocked,
            avg_risk_score=avg_risk,
            governance_summary=dict(gov_summary),
            recommendations=recommendations,
        )

    def generate_report(self) -> CapabilityReport:
        """Generate a comprehensive capability governance report."""
        if not self._records:
            return CapabilityReport()

        agents = {r.agent_id for r in self._records}
        scope_bk: Counter[str] = Counter()
        boundary_bk: Counter[str] = Counter()
        agent_risks: dict[str, list[float]] = {}

        for r in self._records:
            scope_bk[r.scope.value] += 1
            boundary_bk[r.boundary_status.value] += 1
            agent_risks.setdefault(r.agent_id, []).append(r.risk_score)

        violations = sum(
            1
            for r in self._records
            if r.boundary_status in (BoundaryStatus.EXCEEDED, BoundaryStatus.BLOCKED)
        )
        high_risk = [
            aid for aid, scores in agent_risks.items() if (sum(scores) / len(scores)) > 0.5
        ]
        matrix = self.generate_capability_matrix()

        return CapabilityReport(
            total_records=len(self._records),
            unique_agents=len(agents),
            total_violations=violations,
            scope_breakdown=dict(scope_bk),
            boundary_breakdown=dict(boundary_bk),
            high_risk_agents=sorted(high_risk),
            capability_matrix=matrix,
        )

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics."""
        return {
            "total_records": len(self._records),
            "unique_agents": len({r.agent_id for r in self._records}),
            "boundary_violations": sum(
                1
                for r in self._records
                if r.boundary_status in (BoundaryStatus.EXCEEDED, BoundaryStatus.BLOCKED)
            ),
        }

    def clear_data(self) -> None:
        """Clear all stored records."""
        self._records.clear()
        logger.info("agent_capability_tracker.cleared")

    # -- domain methods --

    def track_boundary_violation(
        self, agent_id: str, capability: str, attempted_scope: CapabilityScope
    ) -> dict[str, Any]:
        """Track and record a boundary violation event."""
        existing = [
            r for r in self._records if r.agent_id == agent_id and r.capability == capability
        ]
        granted_scope = existing[-1].scope if existing else CapabilityScope.READ_ONLY
        scope_order = list(CapabilityScope)
        is_escalation = scope_order.index(attempted_scope) > scope_order.index(granted_scope)

        action = GovernanceAction.RESTRICT if is_escalation else GovernanceAction.AUDIT
        status = BoundaryStatus.BLOCKED if is_escalation else BoundaryStatus.EXCEEDED

        rec = self.add_record(
            agent_id=agent_id,
            capability=capability,
            scope=attempted_scope,
            boundary_status=status,
            governance_action=action,
            metadata={"violation_type": "scope_escalation" if is_escalation else "boundary_exceed"},
        )
        logger.warning(
            "agent_capability_tracker.boundary_violation",
            agent_id=agent_id,
            capability=capability,
            attempted_scope=attempted_scope,
            is_escalation=is_escalation,
        )
        return {
            "violation_id": rec.id,
            "agent_id": agent_id,
            "is_escalation": is_escalation,
            "action_taken": action.value,
            "status": status.value,
        }

    def assess_governance_posture(self) -> dict[str, Any]:
        """Assess overall governance posture across all tracked agents."""
        if not self._records:
            return {"posture": "unknown", "score": 0.0, "details": {}}

        total = len(self._records)
        violations = sum(
            1
            for r in self._records
            if r.boundary_status in (BoundaryStatus.EXCEEDED, BoundaryStatus.BLOCKED)
        )
        unrestricted = sum(1 for r in self._records if r.scope == CapabilityScope.UNRESTRICTED)
        approved = sum(1 for r in self._records if r.governance_action == GovernanceAction.APPROVE)

        violation_ratio = violations / total if total > 0 else 0.0
        unrestricted_ratio = unrestricted / total if total > 0 else 0.0
        score = round(max(0.0, 1.0 - violation_ratio * 2 - unrestricted_ratio), 3)

        if score >= 0.8:
            posture = "strong"
        elif score >= 0.5:
            posture = "moderate"
        else:
            posture = "weak"

        return {
            "posture": posture,
            "score": score,
            "total_capabilities": total,
            "violations": violations,
            "unrestricted_count": unrestricted,
            "approved_count": approved,
            "violation_ratio": round(violation_ratio, 3),
        }

    def generate_capability_matrix(self) -> dict[str, list[str]]:
        """Generate agent-to-capability matrix showing all granted capabilities per agent."""
        matrix: dict[str, list[str]] = {}
        for r in self._records:
            if r.agent_id not in matrix:
                matrix[r.agent_id] = []
            entry = f"{r.capability}:{r.scope.value}"
            if entry not in matrix[r.agent_id]:
                matrix[r.agent_id].append(entry)
        return matrix
