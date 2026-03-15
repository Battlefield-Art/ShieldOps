"""ResourceEfficiencyOptimizerEngine — optimize agent resource usage."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ResourceType(StrEnum):
    LLM_TOKENS = "llm_tokens"
    COMPUTE_SECONDS = "compute_seconds"
    MEMORY_MB = "memory_mb"
    API_CALLS = "api_calls"


class OptimizationGoal(StrEnum):
    MINIMIZE_COST = "minimize_cost"
    MAXIMIZE_THROUGHPUT = "maximize_throughput"
    BALANCE = "balance"


class EfficiencyTrend(StrEnum):
    IMPROVING = "improving"
    DEGRADING = "degrading"
    PLATEAU = "plateau"


# --- Models ---


class ResourceEfficiencyOptimizerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    resource_type: ResourceType = ResourceType.LLM_TOKENS
    optimization_goal: OptimizationGoal = OptimizationGoal.BALANCE
    efficiency_trend: EfficiencyTrend = EfficiencyTrend.PLATEAU
    score: float = 0.0
    resource_used: float = 0.0
    resource_budget: float = 0.0
    cost_usd: float = 0.0
    agent_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ResourceEfficiencyOptimizerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    resource_type: ResourceType = ResourceType.LLM_TOKENS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ResourceEfficiencyOptimizerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_resource_type: dict[str, int] = Field(default_factory=dict)
    by_optimization_goal: dict[str, int] = Field(default_factory=dict)
    by_efficiency_trend: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ResourceEfficiencyOptimizerEngine:
    """Optimize agent resource usage (LLM tokens, compute, memory)."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[ResourceEfficiencyOptimizerRecord] = []
        self._analyses: list[ResourceEfficiencyOptimizerAnalysis] = []
        logger.info(
            "resource_efficiency_optimizer_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        resource_type: ResourceType = ResourceType.LLM_TOKENS,
        optimization_goal: OptimizationGoal = OptimizationGoal.BALANCE,
        efficiency_trend: EfficiencyTrend = EfficiencyTrend.PLATEAU,
        score: float = 0.0,
        resource_used: float = 0.0,
        resource_budget: float = 0.0,
        cost_usd: float = 0.0,
        agent_id: str = "",
        service: str = "",
        team: str = "",
    ) -> ResourceEfficiencyOptimizerRecord:
        record = ResourceEfficiencyOptimizerRecord(
            name=name,
            resource_type=resource_type,
            optimization_goal=optimization_goal,
            efficiency_trend=efficiency_trend,
            score=score,
            resource_used=resource_used,
            resource_budget=resource_budget,
            cost_usd=cost_usd,
            agent_id=agent_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "resource_efficiency_optimizer_engine.record_added",
            record_id=record.id,
            name=name,
            resource_type=resource_type.value,
            efficiency_trend=efficiency_trend.value,
        )
        return record

    def get_record(self, record_id: str) -> ResourceEfficiencyOptimizerRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        resource_type: ResourceType | None = None,
        efficiency_trend: EfficiencyTrend | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ResourceEfficiencyOptimizerRecord]:
        results = list(self._records)
        if resource_type is not None:
            results = [r for r in results if r.resource_type == resource_type]
        if efficiency_trend is not None:
            results = [r for r in results if r.efficiency_trend == efficiency_trend]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        resource_type: ResourceType = ResourceType.LLM_TOKENS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ResourceEfficiencyOptimizerAnalysis:
        analysis = ResourceEfficiencyOptimizerAnalysis(
            name=name,
            resource_type=resource_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "resource_efficiency_optimizer_engine.analysis_added",
            name=name,
            resource_type=resource_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_resource_waste(self) -> list[dict[str, Any]]:
        """Identify agents or services wasting resources (high usage, low score)."""
        agent_data: dict[str, list[ResourceEfficiencyOptimizerRecord]] = {}
        for r in self._records:
            agent_data.setdefault(r.agent_id, []).append(r)
        waste: list[dict[str, Any]] = []
        for agent_id, records in agent_data.items():
            scores = [r.score for r in records]
            costs = [r.cost_usd for r in records]
            avg_score = sum(scores) / len(scores)
            total_cost = sum(costs)
            usage_pcts = []
            for r in records:
                if r.resource_budget > 0:
                    usage_pcts.append(r.resource_used / r.resource_budget * 100)
            avg_usage_pct = sum(usage_pcts) / len(usage_pcts) if usage_pcts else 0.0
            if avg_score < self._threshold and total_cost > 0:
                waste.append(
                    {
                        "agent_id": agent_id,
                        "avg_score": round(avg_score, 2),
                        "total_cost_usd": round(total_cost, 2),
                        "avg_budget_usage_pct": round(avg_usage_pct, 1),
                        "waste_severity": (
                            "high" if avg_score < self._threshold * 0.5 else "moderate"
                        ),
                        "sample_count": len(records),
                    }
                )
        return sorted(waste, key=lambda x: x["total_cost_usd"], reverse=True)

    def propose_efficiency_improvements(self) -> list[dict[str, Any]]:
        """Propose improvements to reduce resource usage while maintaining quality."""
        improvements: list[dict[str, Any]] = []
        resource_data: dict[str, list[ResourceEfficiencyOptimizerRecord]] = {}
        for r in self._records:
            resource_data.setdefault(r.resource_type.value, []).append(r)
        for rtype, records in resource_data.items():
            degrading = [r for r in records if r.efficiency_trend == EfficiencyTrend.DEGRADING]
            if degrading:
                avg_cost = sum(r.cost_usd for r in degrading) / len(degrading)
                improvements.append(
                    {
                        "resource_type": rtype,
                        "issue": "degrading_efficiency",
                        "affected_count": len(degrading),
                        "avg_cost_usd": round(avg_cost, 2),
                        "suggestion": f"Review {rtype} usage patterns — efficiency degrading",
                        "priority": "high" if len(degrading) > 3 else "medium",
                    }
                )
            over_budget = [
                r for r in records if r.resource_budget > 0 and r.resource_used > r.resource_budget
            ]
            if over_budget:
                improvements.append(
                    {
                        "resource_type": rtype,
                        "issue": "over_budget",
                        "affected_count": len(over_budget),
                        "avg_overage_pct": round(
                            sum(
                                (r.resource_used - r.resource_budget) / r.resource_budget * 100
                                for r in over_budget
                            )
                            / len(over_budget),
                            1,
                        ),
                        "suggestion": f"Reduce {rtype} consumption or increase budget",
                        "priority": "high",
                    }
                )
        return sorted(
            improvements,
            key=lambda x: 0 if x["priority"] == "high" else 1,
        )

    def compute_cost_per_outcome(self) -> list[dict[str, Any]]:
        """Compute cost efficiency per agent (cost per unit of score)."""
        agent_data: dict[str, list[ResourceEfficiencyOptimizerRecord]] = {}
        for r in self._records:
            agent_data.setdefault(r.agent_id, []).append(r)
        results: list[dict[str, Any]] = []
        for agent_id, records in agent_data.items():
            total_cost = sum(r.cost_usd for r in records)
            avg_score = sum(r.score for r in records) / len(records)
            cost_per_score = round(total_cost / avg_score, 4) if avg_score > 0 else 0.0
            results.append(
                {
                    "agent_id": agent_id,
                    "total_cost_usd": round(total_cost, 2),
                    "avg_score": round(avg_score, 2),
                    "cost_per_score_point": cost_per_score,
                    "efficiency_rating": (
                        "excellent"
                        if cost_per_score < 0.1
                        else "good"
                        if cost_per_score < 0.5
                        else "poor"
                    ),
                    "sample_count": len(records),
                }
            )
        return sorted(results, key=lambda x: x["cost_per_score_point"])

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.resource_type.value
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
                        "resource_type": r.resource_type.value,
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

    def generate_report(self) -> ResourceEfficiencyOptimizerReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.resource_type.value] = by_e1.get(r.resource_type.value, 0) + 1
            by_e2[r.optimization_goal.value] = by_e2.get(r.optimization_goal.value, 0) + 1
            by_e3[r.efficiency_trend.value] = by_e3.get(r.efficiency_trend.value, 0) + 1
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
            recs.append("Resource Efficiency Optimizer Engine is healthy")
        return ResourceEfficiencyOptimizerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_resource_type=by_e1,
            by_optimization_goal=by_e2,
            by_efficiency_trend=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("resource_efficiency_optimizer_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.resource_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "resource_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
