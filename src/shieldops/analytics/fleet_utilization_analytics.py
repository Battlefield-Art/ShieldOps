"""Fleet Utilization Analytics — measure and forecast fleet usage."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class UtilizationMetric(StrEnum):
    CPU = "cpu"
    MEMORY = "memory"
    NETWORK = "network"
    DISK = "disk"
    GPU = "gpu"


class CostEfficiency(StrEnum):
    OPTIMAL = "optimal"
    ACCEPTABLE = "acceptable"
    WASTEFUL = "wasteful"
    CRITICAL = "critical"


class CapacityForecast(StrEnum):
    UNDER_CAPACITY = "under_capacity"
    ADEQUATE = "adequate"
    NEARING_LIMIT = "nearing_limit"
    EXCEEDED = "exceeded"


# --- Models ---


class UtilizationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = ""
    metric: UtilizationMetric = UtilizationMetric.CPU
    efficiency: CostEfficiency = CostEfficiency.OPTIMAL
    forecast: CapacityForecast = CapacityForecast.ADEQUATE
    score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class UtilizationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = ""
    metric: UtilizationMetric = UtilizationMetric.CPU
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class UtilizationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_score: float = 0.0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_efficiency: dict[str, int] = Field(default_factory=dict)
    by_forecast: dict[str, int] = Field(default_factory=dict)
    wasteful_agents: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class FleetUtilizationAnalytics:
    """Measure fleet utilization and cost efficiency."""

    def __init__(
        self,
        max_records: int = 200000,
        utilization_threshold: float = 80.0,
    ) -> None:
        self._max = max_records
        self._threshold = utilization_threshold
        self._records: list[UtilizationRecord] = []
        self._analyses: list[UtilizationAnalysis] = []
        logger.info(
            "fleet_utilization_analytics.init",
            max_records=max_records,
        )

    def add_record(
        self,
        agent_name: str = "",
        metric: UtilizationMetric = (UtilizationMetric.CPU),
        efficiency: CostEfficiency = (CostEfficiency.OPTIMAL),
        forecast: CapacityForecast = (CapacityForecast.ADEQUATE),
        score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> UtilizationRecord:
        rec = UtilizationRecord(
            agent_name=agent_name,
            metric=metric,
            efficiency=efficiency,
            forecast=forecast,
            score=score,
            service=service,
            team=team,
        )
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "fleet_utilization.record_added",
            record_id=rec.id,
        )
        return rec

    def process(self, key: str) -> UtilizationAnalysis:
        matches = [r for r in self._records if r.agent_name == key]
        total = sum(r.score for r in matches)
        avg = total / len(matches) if matches else 0.0
        analysis = UtilizationAnalysis(
            agent_name=key,
            analysis_score=round(avg, 2),
            threshold=self._threshold,
            breached=avg > self._threshold,
            description=(f"Analyzed {len(matches)} agents"),
        )
        self._analyses.append(analysis)
        return analysis

    # -- domain methods ---

    def measure_utilization(
        self,
    ) -> dict[str, Any]:
        """Aggregate utilization by metric type."""
        buckets: dict[str, list[float]] = {}
        for r in self._records:
            buckets.setdefault(r.metric.value, []).append(r.score)
        result: dict[str, Any] = {}
        for metric, scores in buckets.items():
            result[metric] = {
                "count": len(scores),
                "avg": round(sum(scores) / len(scores), 2),
            }
        return result

    def calculate_cost_efficiency(
        self,
    ) -> dict[str, Any]:
        """Summarize cost efficiency distribution."""
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.efficiency.value
            dist[k] = dist.get(k, 0) + 1
        wasteful = dist.get(CostEfficiency.WASTEFUL.value, 0)
        return {
            "distribution": dist,
            "wasteful_count": wasteful,
            "total": len(self._records),
        }

    def forecast_capacity(
        self,
    ) -> dict[str, Any]:
        """Summarize capacity forecast status."""
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.forecast.value
            dist[k] = dist.get(k, 0) + 1
        exceeded = dist.get(CapacityForecast.EXCEEDED.value, 0)
        return {
            "distribution": dist,
            "exceeded_count": exceeded,
            "total": len(self._records),
        }

    # -- report / stats ---

    def generate_report(self) -> UtilizationReport:
        by_metric: dict[str, int] = {}
        by_eff: dict[str, int] = {}
        by_fc: dict[str, int] = {}
        for r in self._records:
            m = r.metric.value
            by_metric[m] = by_metric.get(m, 0) + 1
            e = r.efficiency.value
            by_eff[e] = by_eff.get(e, 0) + 1
            f = r.forecast.value
            by_fc[f] = by_fc.get(f, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        waste = [r.agent_name for r in self._records if r.efficiency == CostEfficiency.WASTEFUL][:5]
        recs: list[str] = []
        if waste:
            recs.append(f"{len(waste)} agent(s) wasteful")
        if not recs:
            recs.append("Fleet utilization optimal")
        return UtilizationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_score=avg,
            by_metric=by_metric,
            by_efficiency=by_eff,
            by_forecast=by_fc,
            wasteful_agents=waste,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.metric.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "metric_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("fleet_utilization_analytics.cleared")
        return {"status": "cleared"}
