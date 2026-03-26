"""Analyst Productivity — measure AI productivity gains."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TaskType(StrEnum):
    ALERT_TRIAGE = "alert_triage"
    INCIDENT_INVESTIGATION = "incident_investigation"
    THREAT_HUNTING = "threat_hunting"
    REPORT_GENERATION = "report_generation"
    PLAYBOOK_EXECUTION = "playbook_execution"


class AutomationLevel(StrEnum):
    FULLY_MANUAL = "fully_manual"
    SEMI_AUTOMATED = "semi_automated"
    MOSTLY_AUTOMATED = "mostly_automated"
    FULLY_AUTOMATED = "fully_automated"
    AI_ASSISTED = "ai_assisted"


class ProductivityMetric(StrEnum):
    TIME_SAVINGS = "time_savings"
    CASE_THROUGHPUT = "case_throughput"
    ACCURACY = "accuracy"
    COST_REDUCTION = "cost_reduction"
    MTTR_IMPROVEMENT = "mttr_improvement"


# --- Models ---


class AnalystProductivityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str = ""
    task_type: TaskType = TaskType.ALERT_TRIAGE
    automation: AutomationLevel = AutomationLevel.AI_ASSISTED
    metric: ProductivityMetric = ProductivityMetric.TIME_SAVINGS
    analyst_id: str = ""
    manual_time_min: float = 0.0
    ai_assisted_time_min: float = 0.0
    cases_handled: int = 0
    accuracy_pct: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AnalystProductivityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str = ""
    task_type: TaskType = TaskType.ALERT_TRIAGE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AnalystProductivityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_time_savings_pct: float = 0.0
    total_cases: int = 0
    by_task_type: dict[str, int] = Field(default_factory=dict)
    by_automation: dict[str, int] = Field(default_factory=dict)
    by_metric: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AnalystProductivityEngine:
    """Measure analyst productivity from AI."""

    def __init__(
        self,
        max_records: int = 200000,
        savings_threshold: float = 30.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = savings_threshold
        self._records: list[AnalystProductivityRecord] = []
        self._analyses: list[AnalystProductivityAnalysis] = []
        logger.info(
            "analyst_productivity.initialized",
            max_records=max_records,
            savings_threshold=savings_threshold,
        )

    # -- record / get / list -----------------------------------

    def add_record(
        self,
        task_id: str,
        task_type: TaskType = TaskType.ALERT_TRIAGE,
        automation: AutomationLevel = (AutomationLevel.AI_ASSISTED),
        metric: ProductivityMetric = (ProductivityMetric.TIME_SAVINGS),
        analyst_id: str = "",
        manual_time_min: float = 0.0,
        ai_assisted_time_min: float = 0.0,
        cases_handled: int = 0,
        accuracy_pct: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> AnalystProductivityRecord:
        record = AnalystProductivityRecord(
            task_id=task_id,
            task_type=task_type,
            automation=automation,
            metric=metric,
            analyst_id=analyst_id,
            manual_time_min=manual_time_min,
            ai_assisted_time_min=(ai_assisted_time_min),
            cases_handled=cases_handled,
            accuracy_pct=accuracy_pct,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "analyst_productivity.record_added",
            record_id=record.id,
            task_id=task_id,
            task_type=task_type.value,
            automation=automation.value,
        )
        return record

    def get_record(self, record_id: str) -> AnalystProductivityRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        task_type: TaskType | None = None,
        automation: AutomationLevel | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AnalystProductivityRecord]:
        results = list(self._records)
        if task_type is not None:
            results = [r for r in results if r.task_type == task_type]
        if automation is not None:
            results = [r for r in results if r.automation == automation]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def process(self, task_id: str) -> AnalystProductivityAnalysis:
        matched = [r for r in self._records if r.task_id == task_id]
        savings_list: list[float] = []
        for r in matched:
            if r.manual_time_min > 0:
                saved = round(
                    (r.manual_time_min - r.ai_assisted_time_min) / r.manual_time_min * 100,
                    2,
                )
                savings_list.append(saved)
        avg = (
            round(
                sum(savings_list) / len(savings_list),
                2,
            )
            if savings_list
            else 0.0
        )
        breached = avg < self._threshold
        analysis = AnalystProductivityAnalysis(
            task_id=task_id,
            task_type=(matched[-1].task_type if matched else TaskType.ALERT_TRIAGE),
            analysis_score=avg,
            threshold=self._threshold,
            breached=breached,
            description=(f"Savings {avg}% for {task_id}"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ------------------------------------

    def measure_time_savings(
        self,
    ) -> dict[str, Any]:
        """Measure time savings from AI assistance."""
        if not self._records:
            return {
                "total_tasks": 0,
                "avg_savings_pct": 0.0,
            }
        savings: list[float] = []
        total_manual = 0.0
        total_ai = 0.0
        for r in self._records:
            total_manual += r.manual_time_min
            total_ai += r.ai_assisted_time_min
            if r.manual_time_min > 0:
                s = round(
                    (r.manual_time_min - r.ai_assisted_time_min) / r.manual_time_min * 100,
                    2,
                )
                savings.append(s)
        avg_savings = round(sum(savings) / len(savings), 2) if savings else 0.0
        total_saved = round(total_manual - total_ai, 2)
        by_type: dict[str, float] = {}
        type_counts: dict[str, int] = {}
        for r in self._records:
            key = r.task_type.value
            if r.manual_time_min > 0:
                s = (r.manual_time_min - r.ai_assisted_time_min) / r.manual_time_min * 100
                by_type[key] = by_type.get(key, 0.0) + s
                type_counts[key] = type_counts.get(key, 0) + 1
        type_avg = {k: round(by_type[k] / type_counts[k], 2) for k in by_type}
        return {
            "total_tasks": len(self._records),
            "avg_savings_pct": avg_savings,
            "total_hours_saved": round(total_saved / 60, 2),
            "by_task_type": type_avg,
        }

    def calculate_case_throughput(
        self,
    ) -> dict[str, Any]:
        """Calculate case throughput metrics."""
        total_cases = sum(r.cases_handled for r in self._records)
        by_type: dict[str, int] = {}
        for r in self._records:
            key = r.task_type.value
            by_type[key] = by_type.get(key, 0) + r.cases_handled
        by_analyst: dict[str, int] = {}
        for r in self._records:
            key = r.analyst_id
            by_analyst[key] = by_analyst.get(key, 0) + r.cases_handled
        top_analysts = sorted(
            by_analyst.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:5]
        return {
            "total_cases": total_cases,
            "total_tasks": len(self._records),
            "avg_cases_per_task": (
                round(
                    total_cases / len(self._records),
                    2,
                )
                if self._records
                else 0.0
            ),
            "by_task_type": by_type,
            "top_analysts": [{"analyst_id": a, "cases": c} for a, c in top_analysts],
        }

    def benchmark_vs_manual(
        self,
    ) -> dict[str, Any]:
        """Benchmark AI-assisted vs manual work."""
        if not self._records:
            return {
                "total_tasks": 0,
                "improvement_factor": 0.0,
            }
        manual_total = sum(r.manual_time_min for r in self._records)
        ai_total = sum(r.ai_assisted_time_min for r in self._records)
        improvement = round(manual_total / ai_total, 2) if ai_total > 0 else 0.0
        accuracy_vals = [r.accuracy_pct for r in self._records if r.accuracy_pct > 0]
        avg_accuracy = (
            round(
                sum(accuracy_vals) / len(accuracy_vals),
                2,
            )
            if accuracy_vals
            else 0.0
        )
        return {
            "total_tasks": len(self._records),
            "manual_hours": round(manual_total / 60, 2),
            "ai_assisted_hours": round(ai_total / 60, 2),
            "improvement_factor": improvement,
            "avg_accuracy_pct": avg_accuracy,
            "meets_threshold": improvement > (self._threshold / 100 + 1),
        }

    # -- report / stats ----------------------------------------

    def generate_report(
        self,
    ) -> AnalystProductivityReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.task_type.value] = by_e1.get(r.task_type.value, 0) + 1
            by_e2[r.automation.value] = by_e2.get(r.automation.value, 0) + 1
            by_e3[r.metric.value] = by_e3.get(r.metric.value, 0) + 1
        savings: list[float] = []
        for r in self._records:
            if r.manual_time_min > 0:
                s = round(
                    (r.manual_time_min - r.ai_assisted_time_min) / r.manual_time_min * 100,
                    2,
                )
                savings.append(s)
        avg_savings = round(sum(savings) / len(savings), 2) if savings else 0.0
        total_cases = sum(r.cases_handled for r in self._records)
        gap_count = sum(1 for s in savings if s < self._threshold)
        top_gaps = [
            r.task_id
            for r in self._records
            if r.manual_time_min > 0
            and ((r.manual_time_min - r.ai_assisted_time_min) / r.manual_time_min * 100)
            < self._threshold
        ][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} task(s) below savings threshold")
        if avg_savings < self._threshold:
            recs.append(f"Avg savings {avg_savings}% below {self._threshold}% target")
        if not recs:
            recs.append("Analyst Productivity is healthy")
        return AnalystProductivityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_time_savings_pct=avg_savings,
            total_cases=total_cases,
            by_task_type=by_e1,
            by_automation=by_e2,
            by_metric=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("analyst_productivity.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.task_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "task_type_distribution": e1_dist,
            "unique_analysts": len({r.analyst_id for r in self._records}),
            "total_cases": sum(r.cases_handled for r in self._records),
        }
