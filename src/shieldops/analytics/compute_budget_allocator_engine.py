"""Compute Budget Allocator Engine —
allocate experiment budgets, detect waste,
and forecast budget exhaustion."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BudgetUnit(StrEnum):
    GPU_HOURS = "gpu_hours"
    CPU_HOURS = "cpu_hours"
    MEMORY_GB_HOURS = "memory_gb_hours"
    API_CALLS = "api_calls"


class AllocationStrategy(StrEnum):
    EQUAL_SPLIT = "equal_split"
    PROPORTIONAL = "proportional"
    PRIORITY_WEIGHTED = "priority_weighted"
    ADAPTIVE = "adaptive"


class BudgetStatus(StrEnum):
    UNDER_BUDGET = "under_budget"
    NEAR_LIMIT = "near_limit"
    AT_LIMIT = "at_limit"
    EXCEEDED = "exceeded"


# --- Models ---


class ComputeBudgetRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    unit: BudgetUnit = BudgetUnit.CPU_HOURS
    strategy: AllocationStrategy = AllocationStrategy.EQUAL_SPLIT
    status: BudgetStatus = BudgetStatus.UNDER_BUDGET
    allocated: float = 0.0
    consumed: float = 0.0
    priority: float = 1.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ComputeBudgetAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    utilization_pct: float = 0.0
    status: BudgetStatus = BudgetStatus.UNDER_BUDGET
    waste_detected: bool = False
    days_until_exhaustion: float = -1.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ComputeBudgetReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    total_allocated: float = 0.0
    total_consumed: float = 0.0
    by_unit: dict[str, int] = Field(default_factory=dict)
    by_strategy: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    top_consumers: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ComputeBudgetAllocatorEngine:
    """Allocate experiment budgets, detect waste,
    and forecast budget exhaustion."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[ComputeBudgetRecord] = []
        self._analyses: dict[str, ComputeBudgetAnalysis] = {}
        logger.info(
            "compute_budget_allocator.init",
            max_records=max_records,
        )

    def add_record(
        self,
        experiment_id: str = "",
        unit: BudgetUnit = BudgetUnit.CPU_HOURS,
        strategy: AllocationStrategy = AllocationStrategy.EQUAL_SPLIT,
        status: BudgetStatus = BudgetStatus.UNDER_BUDGET,
        allocated: float = 0.0,
        consumed: float = 0.0,
        priority: float = 1.0,
        description: str = "",
    ) -> ComputeBudgetRecord:
        record = ComputeBudgetRecord(
            experiment_id=experiment_id,
            unit=unit,
            strategy=strategy,
            status=status,
            allocated=allocated,
            consumed=consumed,
            priority=priority,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "compute_budget.record_added",
            record_id=record.id,
            experiment_id=experiment_id,
        )
        return record

    def process(self, key: str) -> ComputeBudgetAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        util = round((rec.consumed / rec.allocated * 100.0) if rec.allocated > 0 else 0.0, 2)
        waste = util < 20.0 and rec.allocated > 0
        exhaustion = -1.0
        if rec.consumed > 0 and rec.allocated > rec.consumed:
            rate = rec.consumed / max((time.time() - rec.created_at) / 3600.0, 0.001)
            remaining = rec.allocated - rec.consumed
            exhaustion = round(remaining / rate / 24.0, 2) if rate > 0 else -1.0
        analysis = ComputeBudgetAnalysis(
            experiment_id=rec.experiment_id,
            utilization_pct=util,
            status=rec.status,
            waste_detected=waste,
            days_until_exhaustion=exhaustion,
            description=f"Experiment {rec.experiment_id} util={util}%",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ComputeBudgetReport:
        by_u: dict[str, int] = {}
        by_s: dict[str, int] = {}
        by_st: dict[str, int] = {}
        total_alloc = 0.0
        total_cons = 0.0
        for r in self._records:
            by_u[r.unit.value] = by_u.get(r.unit.value, 0) + 1
            by_s[r.strategy.value] = by_s.get(r.strategy.value, 0) + 1
            by_st[r.status.value] = by_st.get(r.status.value, 0) + 1
            total_alloc += r.allocated
            total_cons += r.consumed
        exp_cons: dict[str, float] = {}
        for r in self._records:
            exp_cons[r.experiment_id] = exp_cons.get(r.experiment_id, 0.0) + r.consumed
        top = sorted(exp_cons, key=lambda x: exp_cons[x], reverse=True)[:10]
        recs: list[str] = []
        exceeded = by_st.get("exceeded", 0)
        if exceeded > 0:
            recs.append(f"{exceeded} experiments exceeded budget")
        near = by_st.get("near_limit", 0)
        if near > 0:
            recs.append(f"{near} experiments near budget limit")
        if not recs:
            recs.append("Budget utilization is healthy")
        return ComputeBudgetReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            total_allocated=round(total_alloc, 2),
            total_consumed=round(total_cons, 2),
            by_unit=by_u,
            by_strategy=by_s,
            by_status=by_st,
            top_consumers=top,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        u_dist: dict[str, int] = {}
        for r in self._records:
            u_dist[r.unit.value] = u_dist.get(r.unit.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "unit_distribution": u_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("compute_budget_allocator.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def allocate_experiment_budget(
        self,
        total_budget: float,
        experiment_ids: list[str],
    ) -> list[dict[str, Any]]:
        """Allocate budget across experiments by strategy."""
        if not experiment_ids or total_budget <= 0:
            return []
        priorities: dict[str, float] = {}
        for r in self._records:
            if r.experiment_id in experiment_ids:
                priorities[r.experiment_id] = max(priorities.get(r.experiment_id, 0.0), r.priority)
        for eid in experiment_ids:
            if eid not in priorities:
                priorities[eid] = 1.0
        total_priority = sum(priorities[e] for e in experiment_ids)
        results: list[dict[str, Any]] = []
        for eid in experiment_ids:
            weight = priorities[eid] / total_priority if total_priority > 0 else 1.0
            alloc = round(total_budget * weight, 4)
            results.append(
                {
                    "experiment_id": eid,
                    "allocated": alloc,
                    "priority": priorities[eid],
                    "weight": round(weight, 4),
                }
            )
        results.sort(key=lambda x: x["allocated"], reverse=True)
        return results

    def detect_budget_waste(self) -> list[dict[str, Any]]:
        """Detect experiments with low utilization (waste)."""
        exp_data: dict[str, dict[str, float]] = {}
        for r in self._records:
            if r.experiment_id not in exp_data:
                exp_data[r.experiment_id] = {"allocated": 0.0, "consumed": 0.0}
            exp_data[r.experiment_id]["allocated"] += r.allocated
            exp_data[r.experiment_id]["consumed"] += r.consumed
        results: list[dict[str, Any]] = []
        for eid, data in exp_data.items():
            alloc = data["allocated"]
            cons = data["consumed"]
            if alloc <= 0:
                continue
            util = cons / alloc * 100.0
            wasted = alloc - cons
            if util < 30.0:
                results.append(
                    {
                        "experiment_id": eid,
                        "utilization_pct": round(util, 2),
                        "wasted_units": round(wasted, 4),
                        "severity": "high" if util < 10.0 else "medium",
                    }
                )
        results.sort(key=lambda x: x["utilization_pct"])
        return results

    def forecast_budget_exhaustion(self) -> list[dict[str, Any]]:
        """Forecast when each experiment will exhaust its budget."""
        exp_data: dict[str, dict[str, float]] = {}
        for r in self._records:
            if r.experiment_id not in exp_data:
                exp_data[r.experiment_id] = {
                    "allocated": 0.0,
                    "consumed": 0.0,
                    "age_hours": 0.0,
                }
            exp_data[r.experiment_id]["allocated"] += r.allocated
            exp_data[r.experiment_id]["consumed"] += r.consumed
            age = (time.time() - r.created_at) / 3600.0
            exp_data[r.experiment_id]["age_hours"] = max(
                exp_data[r.experiment_id]["age_hours"], age
            )
        results: list[dict[str, Any]] = []
        for eid, data in exp_data.items():
            cons = data["consumed"]
            alloc = data["allocated"]
            age = max(data["age_hours"], 0.001)
            if cons <= 0 or alloc <= 0:
                continue
            rate_per_hour = cons / age
            remaining = alloc - cons
            hours_left = remaining / rate_per_hour if rate_per_hour > 0 else -1.0
            days_left = round(hours_left / 24.0, 2) if hours_left >= 0 else -1.0
            results.append(
                {
                    "experiment_id": eid,
                    "days_until_exhaustion": days_left,
                    "consumption_rate_per_hour": round(rate_per_hour, 4),
                    "remaining_units": round(remaining, 4),
                    "urgent": 0 <= days_left <= 1,
                }
            )
        results.sort(
            key=lambda x: x["days_until_exhaustion"] if x["days_until_exhaustion"] >= 0 else 9999.0
        )
        return results
