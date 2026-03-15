"""Resource Aware Execution Engine —
enforce resource constraints, predict needs,
and optimize resource utilization."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ResourceConstraint(StrEnum):
    MEMORY_CAP = "memory_cap"
    CPU_CAP = "cpu_cap"
    TIME_LIMIT = "time_limit"
    COST_CEILING = "cost_ceiling"


class ExecutionState(StrEnum):
    RUNNING = "running"
    THROTTLED = "throttled"
    PAUSED = "paused"
    TERMINATED = "terminated"


class ConstraintViolation(StrEnum):
    SOFT_BREACH = "soft_breach"
    HARD_BREACH = "hard_breach"
    PROJECTED_BREACH = "projected_breach"
    NO_VIOLATION = "no_violation"


# --- Models ---


class ResourceAwareRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    constraint: ResourceConstraint = ResourceConstraint.CPU_CAP
    state: ExecutionState = ExecutionState.RUNNING
    violation: ConstraintViolation = ConstraintViolation.NO_VIOLATION
    limit_value: float = 0.0
    current_value: float = 0.0
    projected_value: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ResourceAwareAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    violation: ConstraintViolation = ConstraintViolation.NO_VIOLATION
    utilization_pct: float = 0.0
    recommended_state: ExecutionState = ExecutionState.RUNNING
    headroom_pct: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ResourceAwareReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    by_constraint: dict[str, int] = Field(default_factory=dict)
    by_state: dict[str, int] = Field(default_factory=dict)
    by_violation: dict[str, int] = Field(default_factory=dict)
    top_violators: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ResourceAwareExecutionEngine:
    """Enforce resource constraints, predict resource needs,
    and optimize resource utilization."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[ResourceAwareRecord] = []
        self._analyses: dict[str, ResourceAwareAnalysis] = {}
        logger.info(
            "resource_aware_execution.init",
            max_records=max_records,
        )

    def add_record(
        self,
        agent_id: str = "",
        constraint: ResourceConstraint = ResourceConstraint.CPU_CAP,
        state: ExecutionState = ExecutionState.RUNNING,
        violation: ConstraintViolation = ConstraintViolation.NO_VIOLATION,
        limit_value: float = 0.0,
        current_value: float = 0.0,
        projected_value: float = 0.0,
        description: str = "",
    ) -> ResourceAwareRecord:
        record = ResourceAwareRecord(
            agent_id=agent_id,
            constraint=constraint,
            state=state,
            violation=violation,
            limit_value=limit_value,
            current_value=current_value,
            projected_value=projected_value,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "resource_aware.record_added",
            record_id=record.id,
            agent_id=agent_id,
        )
        return record

    def process(self, key: str) -> ResourceAwareAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        util = round(
            (rec.current_value / rec.limit_value * 100.0) if rec.limit_value > 0 else 0.0, 2
        )
        headroom = round(max(0.0, 100.0 - util), 2)
        recommended = ExecutionState.RUNNING
        if util >= 100.0:
            recommended = ExecutionState.TERMINATED
        elif util >= 90.0:
            recommended = ExecutionState.THROTTLED
        elif util >= 75.0:
            recommended = ExecutionState.PAUSED
        analysis = ResourceAwareAnalysis(
            agent_id=rec.agent_id,
            violation=rec.violation,
            utilization_pct=util,
            recommended_state=recommended,
            headroom_pct=headroom,
            description=f"Agent {rec.agent_id} util={util}% headroom={headroom}%",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ResourceAwareReport:
        by_c: dict[str, int] = {}
        by_s: dict[str, int] = {}
        by_v: dict[str, int] = {}
        for r in self._records:
            by_c[r.constraint.value] = by_c.get(r.constraint.value, 0) + 1
            by_s[r.state.value] = by_s.get(r.state.value, 0) + 1
            by_v[r.violation.value] = by_v.get(r.violation.value, 0) + 1
        agent_violations: dict[str, int] = {}
        for r in self._records:
            if r.violation != ConstraintViolation.NO_VIOLATION:
                agent_violations[r.agent_id] = agent_violations.get(r.agent_id, 0) + 1
        top_violators = sorted(agent_violations, key=lambda x: agent_violations[x], reverse=True)[
            :10
        ]
        recs_list: list[str] = []
        hard = by_v.get("hard_breach", 0)
        if hard > 0:
            recs_list.append(f"{hard} hard constraint breaches detected")
        projected = by_v.get("projected_breach", 0)
        if projected > 0:
            recs_list.append(f"{projected} projected breaches — scale resources")
        if not recs_list:
            recs_list.append("Resource constraints are within bounds")
        return ResourceAwareReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            by_constraint=by_c,
            by_state=by_s,
            by_violation=by_v,
            top_violators=top_violators,
            recommendations=recs_list,
        )

    def get_stats(self) -> dict[str, Any]:
        c_dist: dict[str, int] = {}
        for r in self._records:
            c_dist[r.constraint.value] = c_dist.get(r.constraint.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "constraint_distribution": c_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("resource_aware_execution.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def enforce_resource_constraints(self) -> list[dict[str, Any]]:
        """Identify agents violating resource constraints."""
        agent_data: dict[str, dict[str, Any]] = {}
        for r in self._records:
            aid = r.agent_id
            if aid not in agent_data:
                agent_data[aid] = {"violations": [], "max_util": 0.0}
            if r.limit_value > 0:
                util = r.current_value / r.limit_value * 100.0
                agent_data[aid]["max_util"] = max(agent_data[aid]["max_util"], util)
            if r.violation != ConstraintViolation.NO_VIOLATION:
                agent_data[aid]["violations"].append(
                    {
                        "constraint": r.constraint.value,
                        "violation": r.violation.value,
                        "current": r.current_value,
                        "limit": r.limit_value,
                    }
                )
        results: list[dict[str, Any]] = []
        for aid, data in agent_data.items():
            if data["violations"]:
                results.append(
                    {
                        "agent_id": aid,
                        "violation_count": len(data["violations"]),
                        "max_utilization_pct": round(data["max_util"], 2),
                        "violations": data["violations"],
                        "action_required": data["max_util"] >= 100.0,
                    }
                )
        results.sort(key=lambda x: x["violation_count"], reverse=True)
        return results

    def predict_resource_needs(self) -> list[dict[str, Any]]:
        """Predict future resource requirements per agent."""
        agent_series: dict[str, list[float]] = {}
        agent_limits: dict[str, float] = {}
        for r in self._records:
            aid = r.agent_id
            agent_series.setdefault(aid, []).append(r.current_value)
            if r.limit_value > 0:
                agent_limits[aid] = r.limit_value
        results: list[dict[str, Any]] = []
        for aid, vals in agent_series.items():
            if len(vals) < 2:
                continue
            growth = (vals[-1] - vals[0]) / len(vals)
            predicted_next = vals[-1] + growth
            limit = agent_limits.get(aid, 0.0)
            projected_util = (predicted_next / limit * 100.0) if limit > 0 else 0.0
            results.append(
                {
                    "agent_id": aid,
                    "current_value": vals[-1],
                    "predicted_next": round(predicted_next, 4),
                    "growth_per_step": round(growth, 4),
                    "projected_utilization_pct": round(projected_util, 2),
                    "limit": limit,
                    "at_risk": projected_util >= 90.0,
                }
            )
        results.sort(key=lambda x: x["projected_utilization_pct"], reverse=True)
        return results

    def optimize_resource_utilization(self) -> list[dict[str, Any]]:
        """Recommend utilization optimizations per agent."""
        agent_utils: dict[str, list[float]] = {}
        for r in self._records:
            if r.limit_value > 0:
                util = r.current_value / r.limit_value * 100.0
                agent_utils.setdefault(r.agent_id, []).append(util)
        results: list[dict[str, Any]] = []
        for aid, utils in agent_utils.items():
            avg_util = sum(utils) / len(utils)
            max_util = max(utils)
            recommendation = "maintain_current"
            if avg_util < 20.0:
                recommendation = "reduce_allocation"
            elif avg_util > 85.0:
                recommendation = "increase_allocation"
            elif max_util > 95.0:
                recommendation = "add_burst_capacity"
            results.append(
                {
                    "agent_id": aid,
                    "avg_utilization_pct": round(avg_util, 2),
                    "max_utilization_pct": round(max_util, 2),
                    "recommendation": recommendation,
                    "samples": len(utils),
                }
            )
        results.sort(key=lambda x: x["avg_utilization_pct"], reverse=True)
        return results
