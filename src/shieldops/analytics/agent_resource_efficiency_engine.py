"""Agent Resource Efficiency Engine — token, API call, compute optimization."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ResourceMetric(StrEnum):
    TOKEN_USAGE = "token_usage"
    API_CALLS = "api_calls"
    COMPUTE_SECONDS = "compute_seconds"
    MEMORY_PEAK = "memory_peak"


class EfficiencyGrade(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"


class OptimizationTarget(StrEnum):
    REDUCE_TOKENS = "reduce_tokens"
    REDUCE_LATENCY = "reduce_latency"
    REDUCE_COST = "reduce_cost"
    IMPROVE_ACCURACY = "improve_accuracy"


# --- Models ---


class EfficiencyRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    resource_metric: ResourceMetric = ResourceMetric.TOKEN_USAGE
    grade: EfficiencyGrade = EfficiencyGrade.GOOD
    optimization_target: OptimizationTarget = OptimizationTarget.REDUCE_TOKENS
    usage_value: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class EfficiencyAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    resource_metric: ResourceMetric = ResourceMetric.TOKEN_USAGE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class EfficiencyReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    poor_efficiency_count: int = 0
    avg_usage_value: float = 0.0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_grade: dict[str, int] = Field(default_factory=dict)
    by_target: dict[str, int] = Field(default_factory=dict)
    top_poor_agents: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentResourceEfficiencyEngine:
    """Track and optimize agent resource efficiency — tokens, API calls, compute."""

    def __init__(
        self,
        max_records: int = 200000,
        efficiency_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._efficiency_threshold = efficiency_threshold
        self._records: list[EfficiencyRecord] = []
        self._analyses: list[EfficiencyAnalysis] = []
        logger.info(
            "agent_resource_efficiency_engine.initialized",
            max_records=max_records,
            efficiency_threshold=efficiency_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        agent_id: str,
        resource_metric: ResourceMetric = ResourceMetric.TOKEN_USAGE,
        grade: EfficiencyGrade = EfficiencyGrade.GOOD,
        optimization_target: OptimizationTarget = OptimizationTarget.REDUCE_TOKENS,
        usage_value: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> EfficiencyRecord:
        record = EfficiencyRecord(
            agent_id=agent_id,
            resource_metric=resource_metric,
            grade=grade,
            optimization_target=optimization_target,
            usage_value=usage_value,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_resource_efficiency_engine.record_added",
            record_id=record.id,
            agent_id=agent_id,
            resource_metric=resource_metric.value,
            usage_value=usage_value,
        )
        return record

    def get_record(self, record_id: str) -> EfficiencyRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        resource_metric: ResourceMetric | None = None,
        grade: EfficiencyGrade | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[EfficiencyRecord]:
        results = list(self._records)
        if resource_metric is not None:
            results = [r for r in results if r.resource_metric == resource_metric]
        if grade is not None:
            results = [r for r in results if r.grade == grade]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        agent_id: str,
        resource_metric: ResourceMetric = ResourceMetric.TOKEN_USAGE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> EfficiencyAnalysis:
        analysis = EfficiencyAnalysis(
            agent_id=agent_id,
            resource_metric=resource_metric,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "agent_resource_efficiency_engine.analysis_added",
            agent_id=agent_id,
            resource_metric=resource_metric.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_efficiency_score(self, agent_id: str) -> dict[str, Any]:
        """Efficiency score — value delivered per resource consumed."""
        agent_records = [r for r in self._records if r.agent_id == agent_id]
        if not agent_records:
            return {
                "agent_id": agent_id,
                "overall_efficiency": 0.0,
                "by_metric": {},
            }
        metric_usage: dict[str, list[float]] = {}
        for r in agent_records:
            metric_usage.setdefault(r.resource_metric.value, []).append(r.usage_value)
        by_metric: dict[str, Any] = {}
        all_avgs: list[float] = []
        for metric, values in metric_usage.items():
            avg = round(sum(values) / len(values), 2)
            by_metric[metric] = {"avg_usage": avg, "count": len(values)}
            all_avgs.append(avg)
        overall = round(sum(all_avgs) / len(all_avgs), 2) if all_avgs else 0.0
        return {
            "agent_id": agent_id,
            "overall_efficiency": overall,
            "by_metric": by_metric,
        }

    def identify_resource_waste(self) -> list[dict[str, Any]]:
        """Find agents with poor resource efficiency (POOR or FAIR grade)."""
        waste: list[dict[str, Any]] = []
        agent_ids = {r.agent_id for r in self._records}
        for aid in agent_ids:
            agent_records = [r for r in self._records if r.agent_id == aid]
            poor_count = sum(
                1 for r in agent_records if r.grade in (EfficiencyGrade.POOR, EfficiencyGrade.FAIR)
            )
            if poor_count == 0:
                continue
            avg_usage = round(
                sum(r.usage_value for r in agent_records) / len(agent_records),
                2,
            )
            waste.append(
                {
                    "agent_id": aid,
                    "poor_count": poor_count,
                    "total_records": len(agent_records),
                    "avg_usage_value": avg_usage,
                    "waste_ratio": round(poor_count / len(agent_records), 2),
                }
            )
        return sorted(waste, key=lambda x: x["waste_ratio"], reverse=True)

    def recommend_optimizations(self) -> list[dict[str, Any]]:
        """Suggest specific optimizations per agent based on usage patterns."""
        recommendations: list[dict[str, Any]] = []
        agent_ids = {r.agent_id for r in self._records}
        for aid in agent_ids:
            agent_records = [r for r in self._records if r.agent_id == aid]
            metric_avg: dict[str, float] = {}
            for r in agent_records:
                metric_avg.setdefault(r.resource_metric.value, [])
            metric_avgs: dict[str, float] = {}
            for r in agent_records:
                metric_avgs.setdefault(r.resource_metric.value, []).append(r.usage_value)  # type: ignore[union-attr]
            computed: dict[str, float] = {}
            for m, vals in metric_avgs.items():
                computed[m] = round(
                    sum(vals) / len(vals),
                    2,  # type: ignore[arg-type]
                )
            worst_metric = (
                max(computed, key=computed.get)  # type: ignore[arg-type]
                if computed
                else None
            )
            if worst_metric and computed[worst_metric] > self._efficiency_threshold:
                target_map = {
                    ResourceMetric.TOKEN_USAGE.value: OptimizationTarget.REDUCE_TOKENS.value,
                    ResourceMetric.API_CALLS.value: OptimizationTarget.REDUCE_COST.value,
                    ResourceMetric.COMPUTE_SECONDS.value: OptimizationTarget.REDUCE_LATENCY.value,
                    ResourceMetric.MEMORY_PEAK.value: OptimizationTarget.REDUCE_COST.value,
                }
                recommendations.append(
                    {
                        "agent_id": aid,
                        "worst_metric": worst_metric,
                        "avg_usage": computed[worst_metric],
                        "recommended_target": target_map.get(
                            worst_metric, OptimizationTarget.REDUCE_COST.value
                        ),
                    }
                )
        return sorted(recommendations, key=lambda x: x["avg_usage"], reverse=True)

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> EfficiencyReport:
        by_metric: dict[str, int] = {}
        by_grade: dict[str, int] = {}
        by_target: dict[str, int] = {}
        for r in self._records:
            by_metric[r.resource_metric.value] = by_metric.get(r.resource_metric.value, 0) + 1
            by_grade[r.grade.value] = by_grade.get(r.grade.value, 0) + 1
            by_target[r.optimization_target.value] = (
                by_target.get(r.optimization_target.value, 0) + 1
            )
        poor_efficiency_count = sum(
            1 for r in self._records if r.grade in (EfficiencyGrade.POOR, EfficiencyGrade.FAIR)
        )
        values = [r.usage_value for r in self._records]
        avg_usage_value = round(sum(values) / len(values), 2) if values else 0.0
        waste_list = self.identify_resource_waste()
        top_poor_agents = [w["agent_id"] for w in waste_list[:5]]
        recs: list[str] = []
        if self._records and poor_efficiency_count > 0:
            recs.append(f"{poor_efficiency_count} record(s) with poor/fair efficiency grade")
        if self._records and avg_usage_value > self._efficiency_threshold:
            recs.append(
                f"Avg usage value {avg_usage_value} above efficiency threshold "
                f"({self._efficiency_threshold})"
            )
        if not recs:
            recs.append("Agent resource efficiency is healthy")
        return EfficiencyReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            poor_efficiency_count=poor_efficiency_count,
            avg_usage_value=avg_usage_value,
            by_metric=by_metric,
            by_grade=by_grade,
            by_target=by_target,
            top_poor_agents=top_poor_agents,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_resource_efficiency_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        metric_dist: dict[str, int] = {}
        for r in self._records:
            key = r.resource_metric.value
            metric_dist[key] = metric_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "efficiency_threshold": self._efficiency_threshold,
            "metric_distribution": metric_dist,
            "unique_agents": len({r.agent_id for r in self._records}),
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
