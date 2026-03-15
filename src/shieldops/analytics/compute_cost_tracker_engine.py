"""Compute Cost Tracker Engine —
compute cost per improvement, detect anomalies,
and forecast total optimization cost."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CostCategory(StrEnum):
    LLM_API_CALLS = "llm_api_calls"
    COMPUTE_INFRASTRUCTURE = "compute_infrastructure"
    EVALUATION_RUNS = "evaluation_runs"
    DATA_PROCESSING = "data_processing"


class CostEfficiency(StrEnum):
    HIGHLY_EFFICIENT = "highly_efficient"
    EFFICIENT = "efficient"
    INEFFICIENT = "inefficient"
    WASTEFUL = "wasteful"


class CostTrend(StrEnum):
    DECREASING = "decreasing"
    STABLE = "stable"
    INCREASING = "increasing"
    SPIKING = "spiking"


# --- Models ---


class ComputeCostRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    category: CostCategory = CostCategory.COMPUTE_INFRASTRUCTURE
    efficiency: CostEfficiency = CostEfficiency.EFFICIENT
    trend: CostTrend = CostTrend.STABLE
    cost_usd: float = 0.0
    improvement_delta: float = 0.0
    units_consumed: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ComputeCostAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    cost_per_improvement: float = 0.0
    efficiency: CostEfficiency = CostEfficiency.EFFICIENT
    trend: CostTrend = CostTrend.STABLE
    anomaly_detected: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ComputeCostReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    total_cost_usd: float = 0.0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_efficiency: dict[str, int] = Field(default_factory=dict)
    by_trend: dict[str, int] = Field(default_factory=dict)
    top_cost_experiments: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ComputeCostTrackerEngine:
    """Compute cost per improvement, detect anomalies,
    and forecast total optimization cost."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[ComputeCostRecord] = []
        self._analyses: dict[str, ComputeCostAnalysis] = {}
        logger.info(
            "compute_cost_tracker.init",
            max_records=max_records,
        )

    def add_record(
        self,
        experiment_id: str = "",
        category: CostCategory = CostCategory.COMPUTE_INFRASTRUCTURE,
        efficiency: CostEfficiency = CostEfficiency.EFFICIENT,
        trend: CostTrend = CostTrend.STABLE,
        cost_usd: float = 0.0,
        improvement_delta: float = 0.0,
        units_consumed: float = 0.0,
        description: str = "",
    ) -> ComputeCostRecord:
        record = ComputeCostRecord(
            experiment_id=experiment_id,
            category=category,
            efficiency=efficiency,
            trend=trend,
            cost_usd=cost_usd,
            improvement_delta=improvement_delta,
            units_consumed=units_consumed,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "compute_cost.record_added",
            record_id=record.id,
            experiment_id=experiment_id,
        )
        return record

    def process(self, key: str) -> ComputeCostAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        cost_per_imp = 0.0
        if rec.improvement_delta > 0:
            cost_per_imp = round(rec.cost_usd / rec.improvement_delta, 6)
        exp_costs = [r.cost_usd for r in self._records if r.experiment_id == rec.experiment_id]
        avg_cost = sum(exp_costs) / len(exp_costs) if exp_costs else 0.0
        anomaly = rec.cost_usd > avg_cost * 3.0 and len(exp_costs) > 3
        analysis = ComputeCostAnalysis(
            experiment_id=rec.experiment_id,
            cost_per_improvement=cost_per_imp,
            efficiency=rec.efficiency,
            trend=rec.trend,
            anomaly_detected=anomaly,
            description=f"Experiment {rec.experiment_id} cost_per_imp=${cost_per_imp:.4f}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ComputeCostReport:
        by_c: dict[str, int] = {}
        by_e: dict[str, int] = {}
        by_t: dict[str, int] = {}
        total_cost = 0.0
        for r in self._records:
            by_c[r.category.value] = by_c.get(r.category.value, 0) + 1
            by_e[r.efficiency.value] = by_e.get(r.efficiency.value, 0) + 1
            by_t[r.trend.value] = by_t.get(r.trend.value, 0) + 1
            total_cost += r.cost_usd
        exp_costs: dict[str, float] = {}
        for r in self._records:
            exp_costs[r.experiment_id] = exp_costs.get(r.experiment_id, 0.0) + r.cost_usd
        top_cost_exps = sorted(exp_costs, key=lambda x: exp_costs[x], reverse=True)[:10]
        recs_list: list[str] = []
        wasteful = by_e.get("wasteful", 0)
        if wasteful > 0:
            recs_list.append(f"{wasteful} wasteful cost records — audit resource usage")
        spiking = by_t.get("spiking", 0)
        if spiking > 0:
            recs_list.append(f"{spiking} cost spikes detected — investigate anomalies")
        if not recs_list:
            recs_list.append("Cost efficiency is within acceptable bounds")
        return ComputeCostReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            total_cost_usd=round(total_cost, 4),
            by_category=by_c,
            by_efficiency=by_e,
            by_trend=by_t,
            top_cost_experiments=top_cost_exps,
            recommendations=recs_list,
        )

    def get_stats(self) -> dict[str, Any]:
        c_dist: dict[str, int] = {}
        for r in self._records:
            c_dist[r.category.value] = c_dist.get(r.category.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "category_distribution": c_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("compute_cost_tracker.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def compute_cost_per_improvement(self) -> list[dict[str, Any]]:
        """Compute cost-per-unit-improvement for each experiment."""
        exp_data: dict[str, dict[str, float]] = {}
        for r in self._records:
            eid = r.experiment_id
            if eid not in exp_data:
                exp_data[eid] = {"total_cost": 0.0, "total_improvement": 0.0}
            exp_data[eid]["total_cost"] += r.cost_usd
            exp_data[eid]["total_improvement"] += r.improvement_delta
        results: list[dict[str, Any]] = []
        for eid, data in exp_data.items():
            total_cost = data["total_cost"]
            total_imp = data["total_improvement"]
            cpi = round(total_cost / total_imp, 6) if total_imp > 0 else float("inf")
            results.append(
                {
                    "experiment_id": eid,
                    "total_cost_usd": round(total_cost, 4),
                    "total_improvement": round(total_imp, 6),
                    "cost_per_improvement": cpi if cpi != float("inf") else -1.0,
                    "roi": round(total_imp / total_cost, 6) if total_cost > 0 else 0.0,
                }
            )
        results.sort(
            key=lambda x: x["cost_per_improvement"] if x["cost_per_improvement"] >= 0 else 9999.0
        )
        return results

    def detect_cost_anomalies(self) -> list[dict[str, Any]]:
        """Detect cost records significantly above average."""
        exp_costs: dict[str, list[float]] = {}
        exp_records: dict[str, list[ComputeCostRecord]] = {}
        for r in self._records:
            exp_costs.setdefault(r.experiment_id, []).append(r.cost_usd)
            exp_records.setdefault(r.experiment_id, []).append(r)
        results: list[dict[str, Any]] = []
        for eid, costs in exp_costs.items():
            if len(costs) < 3:
                continue
            mean_c = sum(costs) / len(costs)
            var = sum((c - mean_c) ** 2 for c in costs) / len(costs)
            std_c = var**0.5
            if std_c == 0:
                continue
            for r in exp_records[eid]:
                z_score = (r.cost_usd - mean_c) / std_c
                if z_score > 2.0:
                    results.append(
                        {
                            "record_id": r.id,
                            "experiment_id": eid,
                            "cost_usd": r.cost_usd,
                            "mean_cost": round(mean_c, 4),
                            "std_cost": round(std_c, 4),
                            "z_score": round(z_score, 2),
                            "category": r.category.value,
                        }
                    )
        results.sort(key=lambda x: x["z_score"], reverse=True)
        return results

    def forecast_total_optimization_cost(self) -> list[dict[str, Any]]:
        """Forecast remaining cost for each active experiment."""
        exp_data: dict[str, dict[str, Any]] = {}
        for r in self._records:
            eid = r.experiment_id
            if eid not in exp_data:
                exp_data[eid] = {
                    "costs": [],
                    "earliest": r.created_at,
                    "latest": r.created_at,
                }
            exp_data[eid]["costs"].append(r.cost_usd)
            exp_data[eid]["earliest"] = min(exp_data[eid]["earliest"], r.created_at)
            exp_data[eid]["latest"] = max(exp_data[eid]["latest"], r.created_at)
        results: list[dict[str, Any]] = []
        for eid, data in exp_data.items():
            costs = data["costs"]
            total_so_far = sum(costs)
            age_hours = max((data["latest"] - data["earliest"]) / 3600.0, 0.001)
            rate_per_hour = total_so_far / age_hours
            forecasted_30d = round(rate_per_hour * 24 * 30, 4)
            results.append(
                {
                    "experiment_id": eid,
                    "total_cost_so_far": round(total_so_far, 4),
                    "cost_rate_per_hour": round(rate_per_hour, 6),
                    "forecasted_30d_usd": forecasted_30d,
                    "data_points": len(costs),
                }
            )
        results.sort(key=lambda x: x["forecasted_30d_usd"], reverse=True)
        return results
