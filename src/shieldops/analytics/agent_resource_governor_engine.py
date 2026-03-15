"""AgentResourceGovernorEngine — Enforce resource limits across agent fleet."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ResourcePolicy(StrEnum):
    ENFORCE = "enforce"
    WARN = "warn"
    MONITOR = "monitor"


class LimitScope(StrEnum):
    PER_AGENT = "per_agent"
    PER_TENANT = "per_tenant"
    GLOBAL = "global"


class BudgetPeriod(StrEnum):
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


# --- Models ---


class AgentResourceGovernorRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    resource_policy: ResourcePolicy = ResourcePolicy.MONITOR
    limit_scope: LimitScope = LimitScope.PER_AGENT
    budget_period: BudgetPeriod = BudgetPeriod.DAILY
    score: float = 0.0
    usage_amount: float = 0.0
    budget_limit: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentResourceGovernorAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    resource_policy: ResourcePolicy = ResourcePolicy.MONITOR
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentResourceGovernorReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_resource_policy: dict[str, int] = Field(default_factory=dict)
    by_limit_scope: dict[str, int] = Field(default_factory=dict)
    by_budget_period: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentResourceGovernorEngine:
    """Enforce resource limits across agent fleet (LLM tokens, compute, API calls)."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AgentResourceGovernorRecord] = []
        self._analyses: list[AgentResourceGovernorAnalysis] = []
        logger.info(
            "agent_resource_governor_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        resource_policy: ResourcePolicy = ResourcePolicy.MONITOR,
        limit_scope: LimitScope = LimitScope.PER_AGENT,
        budget_period: BudgetPeriod = BudgetPeriod.DAILY,
        score: float = 0.0,
        usage_amount: float = 0.0,
        budget_limit: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> AgentResourceGovernorRecord:
        record = AgentResourceGovernorRecord(
            name=name,
            resource_policy=resource_policy,
            limit_scope=limit_scope,
            budget_period=budget_period,
            score=score,
            usage_amount=usage_amount,
            budget_limit=budget_limit,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_resource_governor_engine.record_added",
            record_id=record.id,
            name=name,
            resource_policy=resource_policy.value,
            limit_scope=limit_scope.value,
        )
        return record

    def get_record(self, record_id: str) -> AgentResourceGovernorRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        resource_policy: ResourcePolicy | None = None,
        limit_scope: LimitScope | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AgentResourceGovernorRecord]:
        results = list(self._records)
        if resource_policy is not None:
            results = [r for r in results if r.resource_policy == resource_policy]
        if limit_scope is not None:
            results = [r for r in results if r.limit_scope == limit_scope]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        resource_policy: ResourcePolicy = ResourcePolicy.MONITOR,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AgentResourceGovernorAnalysis:
        analysis = AgentResourceGovernorAnalysis(
            name=name,
            resource_policy=resource_policy,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "agent_resource_governor_engine.analysis_added",
            name=name,
            resource_policy=resource_policy.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def enforce_resource_limits(self) -> list[dict[str, Any]]:
        """Enforce resource limits and identify violations."""
        violations: list[dict[str, Any]] = []
        for r in self._records:
            if r.budget_limit > 0 and r.usage_amount > r.budget_limit:
                utilization = round(r.usage_amount / r.budget_limit * 100, 1)
                violations.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "policy": r.resource_policy.value,
                        "scope": r.limit_scope.value,
                        "usage": r.usage_amount,
                        "limit": r.budget_limit,
                        "utilization_pct": utilization,
                        "action": (
                            "throttled"
                            if r.resource_policy == ResourcePolicy.ENFORCE
                            else "warned"
                            if r.resource_policy == ResourcePolicy.WARN
                            else "logged"
                        ),
                    }
                )
        return sorted(violations, key=lambda x: x["utilization_pct"], reverse=True)

    def detect_budget_violations(self) -> list[dict[str, Any]]:
        """Detect agents/tenants exceeding budget thresholds."""
        svc_data: dict[str, list[AgentResourceGovernorRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        violations: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            total_usage = sum(r.usage_amount for r in records)
            total_budget = sum(r.budget_limit for r in records if r.budget_limit > 0)
            if total_budget > 0 and total_usage > total_budget:
                violations.append(
                    {
                        "service": svc,
                        "total_usage": round(total_usage, 2),
                        "total_budget": round(total_budget, 2),
                        "overage_pct": round((total_usage - total_budget) / total_budget * 100, 1),
                        "record_count": len(records),
                        "severity": ("critical" if total_usage > total_budget * 1.5 else "warning"),
                    }
                )
        return sorted(violations, key=lambda x: x["overage_pct"], reverse=True)

    def recommend_budget_adjustments(self) -> list[dict[str, Any]]:
        """Recommend budget adjustments based on usage patterns."""
        recommendations: list[dict[str, Any]] = []
        svc_data: dict[str, list[AgentResourceGovernorRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        for svc, records in svc_data.items():
            usage_values = [r.usage_amount for r in records]
            budget_values = [r.budget_limit for r in records if r.budget_limit > 0]
            avg_usage = round(sum(usage_values) / len(usage_values), 2)
            avg_budget = round(sum(budget_values) / len(budget_values), 2) if budget_values else 0.0
            if avg_budget > 0:
                utilization = round(avg_usage / avg_budget * 100, 1)
                if utilization > 90:
                    recommendations.append(
                        {
                            "service": svc,
                            "avg_usage": avg_usage,
                            "avg_budget": avg_budget,
                            "utilization_pct": utilization,
                            "action": "increase_budget",
                            "suggestion": (
                                f"Increase budget for {svc} — "
                                f"{utilization}% utilization approaching limit"
                            ),
                        }
                    )
                elif utilization < 30:
                    recommendations.append(
                        {
                            "service": svc,
                            "avg_usage": avg_usage,
                            "avg_budget": avg_budget,
                            "utilization_pct": utilization,
                            "action": "decrease_budget",
                            "suggestion": (
                                f"Reduce budget for {svc} — "
                                f"only {utilization}% utilization, reallocate savings"
                            ),
                        }
                    )
        return sorted(recommendations, key=lambda x: x["utilization_pct"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.resource_policy.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "resource_policy": r.resource_policy.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> AgentResourceGovernorReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.resource_policy.value] = by_e1.get(r.resource_policy.value, 0) + 1
            by_e2[r.limit_scope.value] = by_e2.get(r.limit_scope.value, 0) + 1
            by_e3[r.budget_period.value] = by_e3.get(r.budget_period.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Agent Resource Governor Engine is healthy")
        return AgentResourceGovernorReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_resource_policy=by_e1,
            by_limit_scope=by_e2,
            by_budget_period=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_resource_governor_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.resource_policy.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "resource_policy_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
