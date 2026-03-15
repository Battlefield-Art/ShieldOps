"""FleetIntelligenceEngine — Aggregate intelligence across the entire agent fleet."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class FleetMetric(StrEnum):
    TOTAL_INVOCATIONS = "total_invocations"
    SUCCESS_RATE = "success_rate"
    AVG_LATENCY = "avg_latency"
    COST_PER_RESOLUTION = "cost_per_resolution"


class FleetHealth(StrEnum):
    THRIVING = "thriving"
    STABLE = "stable"
    DECLINING = "declining"
    CRITICAL = "critical"


class StrategicInsight(StrEnum):
    SCALE_UP = "scale_up"
    OPTIMIZE = "optimize"
    CONSOLIDATE = "consolidate"
    RETRAIN = "retrain"


# --- Models ---


class FleetIntelligenceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    fleet_metric: FleetMetric = FleetMetric.TOTAL_INVOCATIONS
    fleet_health: FleetHealth = FleetHealth.STABLE
    strategic_insight: StrategicInsight = StrategicInsight.OPTIMIZE
    score: float = 0.0
    invocations: int = 0
    success_count: int = 0
    failure_count: int = 0
    avg_latency_ms: float = 0.0
    cost: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class FleetIntelligenceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    fleet_metric: FleetMetric = FleetMetric.TOTAL_INVOCATIONS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class FleetIntelligenceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_fleet_metric: dict[str, int] = Field(default_factory=dict)
    by_fleet_health: dict[str, int] = Field(default_factory=dict)
    by_strategic_insight: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class FleetIntelligenceEngine:
    """Aggregate intelligence across the entire agent fleet engine."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[FleetIntelligenceRecord] = []
        self._analyses: list[FleetIntelligenceAnalysis] = []
        logger.info(
            "fleet_intelligence_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        fleet_metric: FleetMetric = FleetMetric.TOTAL_INVOCATIONS,
        fleet_health: FleetHealth = FleetHealth.STABLE,
        strategic_insight: StrategicInsight = StrategicInsight.OPTIMIZE,
        score: float = 0.0,
        invocations: int = 0,
        success_count: int = 0,
        failure_count: int = 0,
        avg_latency_ms: float = 0.0,
        cost: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> FleetIntelligenceRecord:
        record = FleetIntelligenceRecord(
            name=name,
            fleet_metric=fleet_metric,
            fleet_health=fleet_health,
            strategic_insight=strategic_insight,
            score=score,
            invocations=invocations,
            success_count=success_count,
            failure_count=failure_count,
            avg_latency_ms=avg_latency_ms,
            cost=cost,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "fleet_intelligence_engine.record_added",
            record_id=record.id,
            name=name,
            fleet_metric=fleet_metric.value,
            fleet_health=fleet_health.value,
        )
        return record

    def get_record(self, record_id: str) -> FleetIntelligenceRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        fleet_metric: FleetMetric | None = None,
        fleet_health: FleetHealth | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[FleetIntelligenceRecord]:
        results = list(self._records)
        if fleet_metric is not None:
            results = [r for r in results if r.fleet_metric == fleet_metric]
        if fleet_health is not None:
            results = [r for r in results if r.fleet_health == fleet_health]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        fleet_metric: FleetMetric = FleetMetric.TOTAL_INVOCATIONS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> FleetIntelligenceAnalysis:
        analysis = FleetIntelligenceAnalysis(
            name=name,
            fleet_metric=fleet_metric,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "fleet_intelligence_engine.analysis_added",
            name=name,
            fleet_metric=fleet_metric.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_fleet_health(self) -> list[dict[str, Any]]:
        """Compute health metrics for the entire fleet grouped by service."""
        svc_data: dict[str, list[FleetIntelligenceRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            total_invocations = sum(r.invocations for r in records)
            total_success = sum(r.success_count for r in records)
            total_failure = sum(r.failure_count for r in records)
            success_rate = (
                round(total_success / (total_success + total_failure), 4)
                if (total_success + total_failure) > 0
                else 0.0
            )
            avg_score = round(sum(r.score for r in records) / len(records), 2)
            total_cost = round(sum(r.cost for r in records), 2)
            health_counts: dict[str, int] = {}
            for r in records:
                health_counts[r.fleet_health.value] = health_counts.get(r.fleet_health.value, 0) + 1
            results.append(
                {
                    "service": svc,
                    "total_invocations": total_invocations,
                    "success_rate": success_rate,
                    "avg_score": avg_score,
                    "total_cost": total_cost,
                    "health_distribution": health_counts,
                    "record_count": len(records),
                }
            )
        return sorted(results, key=lambda x: x["success_rate"])

    def identify_underperforming_agents(self) -> list[dict[str, Any]]:
        """Identify agents that are underperforming relative to fleet average."""
        if not self._records:
            return []
        fleet_avg_score = sum(r.score for r in self._records) / len(self._records)
        svc_data: dict[str, list[FleetIntelligenceRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        underperforming: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            avg_score = sum(r.score for r in records) / len(records)
            if avg_score < fleet_avg_score:
                gap = round(fleet_avg_score - avg_score, 2)
                critical_count = sum(1 for r in records if r.fleet_health == FleetHealth.CRITICAL)
                declining_count = sum(1 for r in records if r.fleet_health == FleetHealth.DECLINING)
                underperforming.append(
                    {
                        "service": svc,
                        "avg_score": round(avg_score, 2),
                        "fleet_avg_score": round(fleet_avg_score, 2),
                        "gap": gap,
                        "critical_count": critical_count,
                        "declining_count": declining_count,
                        "record_count": len(records),
                        "severity": ("critical" if critical_count > 0 else "warning"),
                    }
                )
        return sorted(underperforming, key=lambda x: x["gap"], reverse=True)

    def recommend_fleet_strategy(self) -> list[dict[str, Any]]:
        """Recommend strategic actions for the fleet."""
        recommendations: list[dict[str, Any]] = []
        svc_data: dict[str, list[FleetIntelligenceRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        for svc, records in svc_data.items():
            avg_score = sum(r.score for r in records) / len(records)
            total_success = sum(r.success_count for r in records)
            total_failure = sum(r.failure_count for r in records)
            success_rate = (
                total_success / (total_success + total_failure)
                if (total_success + total_failure) > 0
                else 0.0
            )
            total_cost = sum(r.cost for r in records)
            if success_rate < 0.5:
                recommendations.append(
                    {
                        "service": svc,
                        "strategy": StrategicInsight.RETRAIN.value,
                        "priority": "critical",
                        "reason": f"Low success rate ({round(success_rate, 2)})",
                        "suggestion": f"Retrain agent for {svc} — success rate below 50%",
                    }
                )
            elif avg_score < self._threshold:
                recommendations.append(
                    {
                        "service": svc,
                        "strategy": StrategicInsight.OPTIMIZE.value,
                        "priority": "high",
                        "reason": f"Below threshold score ({round(avg_score, 2)})",
                        "suggestion": f"Optimize agent for {svc} — score below threshold",
                    }
                )
            elif total_cost > 0 and success_rate > 0.9:
                cost_per_success = round(total_cost / max(total_success, 1), 2)
                if cost_per_success > 10:
                    recommendations.append(
                        {
                            "service": svc,
                            "strategy": StrategicInsight.CONSOLIDATE.value,
                            "priority": "medium",
                            "reason": f"High cost per resolution ({cost_per_success})",
                            "suggestion": f"Consolidate operations for {svc} to reduce cost",
                        }
                    )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "critical" else 1 if x["priority"] == "high" else 2,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.fleet_metric.value
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
                        "fleet_metric": r.fleet_metric.value,
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

    def generate_report(self) -> FleetIntelligenceReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.fleet_metric.value] = by_e1.get(r.fleet_metric.value, 0) + 1
            by_e2[r.fleet_health.value] = by_e2.get(r.fleet_health.value, 0) + 1
            by_e3[r.strategic_insight.value] = by_e3.get(r.strategic_insight.value, 0) + 1
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
            recs.append("Fleet Intelligence Engine is healthy")
        return FleetIntelligenceReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_fleet_metric=by_e1,
            by_fleet_health=by_e2,
            by_strategic_insight=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("fleet_intelligence_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.fleet_metric.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "fleet_metric_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
