"""Resource Budget Tracker Engine —
track resource consumption of autonomous agents/experiments,
enforce budgets for CPU, memory, API calls, and wall-clock time."""

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
    CPU_SECONDS = "cpu_seconds"
    MEMORY_MB = "memory_mb"
    API_CALLS = "api_calls"
    WALL_CLOCK_SECONDS = "wall_clock_seconds"


class BudgetCompliance(StrEnum):
    COMPLIANT = "compliant"
    WARNING = "warning"
    EXCEEDED = "exceeded"
    UNKNOWN = "unknown"


class ConsumerType(StrEnum):
    AGENT = "agent"
    EXPERIMENT = "experiment"
    PIPELINE = "pipeline"
    SCHEDULED_JOB = "scheduled_job"


# --- Models ---


class ResourceBudgetRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    consumer_id: str = ""
    consumer_type: ConsumerType = ConsumerType.AGENT
    resource_type: ResourceType = ResourceType.CPU_SECONDS
    budget_compliance: BudgetCompliance = BudgetCompliance.UNKNOWN
    allocated: float = 0.0
    consumed: float = 0.0
    utilization_pct: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ResourceBudgetAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    consumer_id: str = ""
    consumer_type: ConsumerType = ConsumerType.AGENT
    total_consumed: float = 0.0
    budget_remaining: float = 0.0
    utilization_pct: float = 0.0
    budget_compliance: BudgetCompliance = BudgetCompliance.UNKNOWN
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ResourceBudgetReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_utilization_pct: float = 0.0
    by_resource_type: dict[str, int] = Field(default_factory=dict)
    by_budget_compliance: dict[str, int] = Field(default_factory=dict)
    by_consumer_type: dict[str, int] = Field(default_factory=dict)
    over_budget_consumers: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ResourceBudgetTrackerEngine:
    """Track resource consumption and enforce budgets for autonomous
    agents, experiments, pipelines, and scheduled jobs."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[ResourceBudgetRecord] = []
        self._analyses: dict[str, ResourceBudgetAnalysis] = {}
        logger.info(
            "resource_budget_tracker.init",
            max_records=max_records,
        )

    def add_record(
        self,
        consumer_id: str = "",
        consumer_type: ConsumerType = ConsumerType.AGENT,
        resource_type: ResourceType = ResourceType.CPU_SECONDS,
        budget_compliance: BudgetCompliance = BudgetCompliance.UNKNOWN,
        allocated: float = 0.0,
        consumed: float = 0.0,
        utilization_pct: float = 0.0,
        description: str = "",
    ) -> ResourceBudgetRecord:
        record = ResourceBudgetRecord(
            consumer_id=consumer_id,
            consumer_type=consumer_type,
            resource_type=resource_type,
            budget_compliance=budget_compliance,
            allocated=allocated,
            consumed=consumed,
            utilization_pct=utilization_pct,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "resource_budget.record_added",
            record_id=record.id,
            consumer_id=consumer_id,
            resource_type=resource_type.value,
        )
        return record

    def process(self, key: str) -> ResourceBudgetAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        # Aggregate all records for this consumer
        consumer_recs = [r for r in self._records if r.consumer_id == rec.consumer_id]
        total_consumed = round(sum(r.consumed for r in consumer_recs), 4)
        total_allocated = sum(r.allocated for r in consumer_recs)
        budget_remaining = round(max(total_allocated - total_consumed, 0.0), 4)
        util_pct = round(total_consumed / total_allocated * 100, 2) if total_allocated > 0 else 0.0
        if util_pct >= 100:
            compliance = BudgetCompliance.EXCEEDED
        elif util_pct >= 80:
            compliance = BudgetCompliance.WARNING
        elif total_allocated > 0:
            compliance = BudgetCompliance.COMPLIANT
        else:
            compliance = BudgetCompliance.UNKNOWN
        analysis = ResourceBudgetAnalysis(
            consumer_id=rec.consumer_id,
            consumer_type=rec.consumer_type,
            total_consumed=total_consumed,
            budget_remaining=budget_remaining,
            utilization_pct=util_pct,
            budget_compliance=compliance,
            description=(f"Consumer {rec.consumer_id} utilization={util_pct:.1f}%"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ResourceBudgetReport:
        by_rt: dict[str, int] = {}
        by_bc: dict[str, int] = {}
        by_ct: dict[str, int] = {}
        for r in self._records:
            by_rt[r.resource_type.value] = by_rt.get(r.resource_type.value, 0) + 1
            by_bc[r.budget_compliance.value] = by_bc.get(r.budget_compliance.value, 0) + 1
            by_ct[r.consumer_type.value] = by_ct.get(r.consumer_type.value, 0) + 1
        utils = [r.utilization_pct for r in self._records]
        avg_util = round(sum(utils) / len(utils), 2) if utils else 0.0
        over_budget = list(
            {
                r.consumer_id
                for r in self._records
                if r.budget_compliance == BudgetCompliance.EXCEEDED
            }
        )
        recs_list: list[str] = []
        exceeded = by_bc.get("exceeded", 0)
        if exceeded > 0:
            recs_list.append(f"{exceeded} record(s) exceeded budget — enforce limits")
        warning = by_bc.get("warning", 0)
        if warning > 0:
            recs_list.append(f"{warning} record(s) approaching budget limit — monitor closely")
        if not recs_list:
            recs_list.append("Resource budget compliance is healthy")
        return ResourceBudgetReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_utilization_pct=avg_util,
            by_resource_type=by_rt,
            by_budget_compliance=by_bc,
            by_consumer_type=by_ct,
            over_budget_consumers=sorted(over_budget),
            recommendations=recs_list,
        )

    def get_stats(self) -> dict[str, Any]:
        rt_dist: dict[str, int] = {}
        for r in self._records:
            rt_dist[r.resource_type.value] = rt_dist.get(r.resource_type.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "resource_type_distribution": rt_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("resource_budget_tracker.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def identify_over_budget_consumers(self) -> list[dict[str, Any]]:
        """Find consumers exceeding their budgets."""
        consumer_data: dict[str, dict[str, Any]] = {}
        for r in self._records:
            cid = r.consumer_id
            if cid not in consumer_data:
                consumer_data[cid] = {
                    "allocated": 0.0,
                    "consumed": 0.0,
                    "consumer_type": r.consumer_type.value,
                }
            consumer_data[cid]["allocated"] += r.allocated
            consumer_data[cid]["consumed"] += r.consumed
        results: list[dict[str, Any]] = []
        for cid, data in consumer_data.items():
            allocated = data["allocated"]
            consumed = data["consumed"]
            if allocated > 0 and consumed > allocated:
                overage_pct = round((consumed - allocated) / allocated * 100, 2)
                results.append(
                    {
                        "consumer_id": cid,
                        "consumer_type": data["consumer_type"],
                        "allocated": round(allocated, 4),
                        "consumed": round(consumed, 4),
                        "overage_pct": overage_pct,
                    }
                )
        results.sort(key=lambda x: x["overage_pct"], reverse=True)
        return results

    def forecast_budget_exhaustion(self, consumer_id: str) -> dict[str, Any]:
        """Predict when a consumer will exhaust its budget."""
        consumer_recs = sorted(
            [r for r in self._records if r.consumer_id == consumer_id],
            key=lambda x: x.created_at,
        )
        if not consumer_recs:
            return {
                "consumer_id": consumer_id,
                "forecast": None,
                "reason": "no_data",
            }
        total_allocated = sum(r.allocated for r in consumer_recs)
        total_consumed = sum(r.consumed for r in consumer_recs)
        if total_consumed <= 0:
            return {
                "consumer_id": consumer_id,
                "total_allocated": round(total_allocated, 4),
                "total_consumed": 0.0,
                "hours_to_exhaustion": float("inf"),
                "status": "no_consumption",
            }
        earliest = consumer_recs[0].created_at
        latest = consumer_recs[-1].created_at
        elapsed_hours = max((latest - earliest) / 3600.0, 0.001)
        rate_per_hour = total_consumed / elapsed_hours
        remaining = max(total_allocated - total_consumed, 0.0)
        hours_to_exhaustion = (
            round(remaining / rate_per_hour, 2) if rate_per_hour > 0 else float("inf")
        )
        return {
            "consumer_id": consumer_id,
            "total_allocated": round(total_allocated, 4),
            "total_consumed": round(total_consumed, 4),
            "rate_per_hour": round(rate_per_hour, 4),
            "hours_to_exhaustion": hours_to_exhaustion,
            "data_points": len(consumer_recs),
        }

    def recommend_budget_adjustments(self) -> list[dict[str, Any]]:
        """Suggest budget increases/decreases based on utilization patterns."""
        consumer_data: dict[str, dict[str, Any]] = {}
        for r in self._records:
            cid = r.consumer_id
            if cid not in consumer_data:
                consumer_data[cid] = {
                    "allocated": 0.0,
                    "consumed": 0.0,
                    "consumer_type": r.consumer_type.value,
                }
            consumer_data[cid]["allocated"] += r.allocated
            consumer_data[cid]["consumed"] += r.consumed
        results: list[dict[str, Any]] = []
        for cid, data in consumer_data.items():
            allocated = data["allocated"]
            consumed = data["consumed"]
            if allocated <= 0:
                continue
            util_pct = round(consumed / allocated * 100, 2)
            if util_pct > 100:
                action = "increase"
                suggested = round(consumed * 1.25, 4)
                reason = "budget exceeded — increase by 25% above actual usage"
            elif util_pct > 80:
                action = "increase"
                suggested = round(allocated * 1.2, 4)
                reason = "approaching limit — increase by 20%"
            elif util_pct < 30:
                action = "decrease"
                suggested = round(consumed * 1.5, 4)
                reason = "significantly under-utilized — reduce to 150% of actual"
            else:
                action = "maintain"
                suggested = allocated
                reason = "utilization is within acceptable range"
            results.append(
                {
                    "consumer_id": cid,
                    "consumer_type": data["consumer_type"],
                    "current_allocated": round(allocated, 4),
                    "current_consumed": round(consumed, 4),
                    "utilization_pct": util_pct,
                    "action": action,
                    "suggested_budget": suggested,
                    "reason": reason,
                }
            )
        results.sort(key=lambda x: x["utilization_pct"], reverse=True)
        return results
