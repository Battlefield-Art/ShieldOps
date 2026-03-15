"""Experiment Lifecycle Engine —
track autonomous experiment proposals, execution, results,
and accept/reject decisions (autoresearch pattern)."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ExperimentPhase(StrEnum):
    PROPOSED = "proposed"
    RUNNING = "running"
    COMPLETED = "completed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class ExperimentDomain(StrEnum):
    ALERT_TUNING = "alert_tuning"
    ROUTING = "routing"
    RUNBOOK = "runbook"
    POLICY = "policy"
    THRESHOLD = "threshold"


class BudgetStatus(StrEnum):
    WITHIN_BUDGET = "within_budget"
    APPROACHING_LIMIT = "approaching_limit"
    EXCEEDED = "exceeded"
    NOT_SET = "not_set"


# --- Models ---


class ExperimentLifecycleRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    experiment_phase: ExperimentPhase = ExperimentPhase.PROPOSED
    experiment_domain: ExperimentDomain = ExperimentDomain.ALERT_TUNING
    budget_status: BudgetStatus = BudgetStatus.NOT_SET
    metric_before: float = 0.0
    metric_after: float = 0.0
    improvement_pct: float = 0.0
    duration_seconds: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ExperimentLifecycleAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    experiment_domain: ExperimentDomain = ExperimentDomain.ALERT_TUNING
    acceptance_rate: float = 0.0
    avg_improvement: float = 0.0
    total_duration: float = 0.0
    budget_status: BudgetStatus = BudgetStatus.NOT_SET
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ExperimentLifecycleReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    overall_acceptance_rate: float = 0.0
    by_experiment_phase: dict[str, int] = Field(default_factory=dict)
    by_experiment_domain: dict[str, int] = Field(default_factory=dict)
    by_budget_status: dict[str, int] = Field(default_factory=dict)
    top_improvements: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ExperimentLifecycleEngine:
    """Track autonomous experiment lifecycle — propose, execute, evaluate,
    accept/reject with fixed resource budgets."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[ExperimentLifecycleRecord] = []
        self._analyses: dict[str, ExperimentLifecycleAnalysis] = {}
        logger.info(
            "experiment_lifecycle_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        experiment_id: str = "",
        experiment_phase: ExperimentPhase = ExperimentPhase.PROPOSED,
        experiment_domain: ExperimentDomain = ExperimentDomain.ALERT_TUNING,
        budget_status: BudgetStatus = BudgetStatus.NOT_SET,
        metric_before: float = 0.0,
        metric_after: float = 0.0,
        improvement_pct: float = 0.0,
        duration_seconds: float = 0.0,
        description: str = "",
    ) -> ExperimentLifecycleRecord:
        record = ExperimentLifecycleRecord(
            experiment_id=experiment_id,
            experiment_phase=experiment_phase,
            experiment_domain=experiment_domain,
            budget_status=budget_status,
            metric_before=metric_before,
            metric_after=metric_after,
            improvement_pct=improvement_pct,
            duration_seconds=duration_seconds,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "experiment_lifecycle.record_added",
            record_id=record.id,
            experiment_id=experiment_id,
            phase=experiment_phase.value,
        )
        return record

    def process(self, key: str) -> ExperimentLifecycleAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        # Gather all records for this experiment
        exp_recs = [r for r in self._records if r.experiment_id == rec.experiment_id]
        accepted = sum(1 for r in exp_recs if r.experiment_phase == ExperimentPhase.ACCEPTED)
        completed = sum(
            1
            for r in exp_recs
            if r.experiment_phase
            in (ExperimentPhase.ACCEPTED, ExperimentPhase.REJECTED, ExperimentPhase.COMPLETED)
        )
        acceptance_rate = round(accepted / completed, 4) if completed > 0 else 0.0
        improvements = [r.improvement_pct for r in exp_recs if r.improvement_pct != 0.0]
        avg_imp = round(sum(improvements) / len(improvements), 4) if improvements else 0.0
        total_dur = round(sum(r.duration_seconds for r in exp_recs), 2)
        analysis = ExperimentLifecycleAnalysis(
            experiment_id=rec.experiment_id,
            experiment_domain=rec.experiment_domain,
            acceptance_rate=acceptance_rate,
            avg_improvement=avg_imp,
            total_duration=total_dur,
            budget_status=rec.budget_status,
            description=(f"Experiment {rec.experiment_id} acceptance_rate={acceptance_rate:.2%}"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ExperimentLifecycleReport:
        by_phase: dict[str, int] = {}
        by_domain: dict[str, int] = {}
        by_budget: dict[str, int] = {}
        for r in self._records:
            by_phase[r.experiment_phase.value] = by_phase.get(r.experiment_phase.value, 0) + 1
            by_domain[r.experiment_domain.value] = by_domain.get(r.experiment_domain.value, 0) + 1
            by_budget[r.budget_status.value] = by_budget.get(r.budget_status.value, 0) + 1
        accepted_count = by_phase.get("accepted", 0)
        terminal_count = accepted_count + by_phase.get("rejected", 0)
        overall_rate = round(accepted_count / terminal_count, 4) if terminal_count > 0 else 0.0
        # Top improvements by experiment_id
        exp_improvements: dict[str, float] = {}
        for r in self._records:
            if r.improvement_pct > 0:
                exp_improvements[r.experiment_id] = max(
                    exp_improvements.get(r.experiment_id, 0.0),
                    r.improvement_pct,
                )
        top_imps = sorted(exp_improvements, key=lambda x: exp_improvements[x], reverse=True)[:10]
        recs_list: list[str] = []
        rejected = by_phase.get("rejected", 0)
        if rejected > 0:
            recs_list.append(f"{rejected} experiment(s) rejected — review failure patterns")
        exceeded = by_budget.get("exceeded", 0)
        if exceeded > 0:
            recs_list.append(f"{exceeded} record(s) exceeded budget — tighten resource limits")
        if not recs_list:
            recs_list.append("Experiment lifecycle is healthy")
        return ExperimentLifecycleReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            overall_acceptance_rate=overall_rate,
            by_experiment_phase=by_phase,
            by_experiment_domain=by_domain,
            by_budget_status=by_budget,
            top_improvements=top_imps,
            recommendations=recs_list,
        )

    def get_stats(self) -> dict[str, Any]:
        phase_dist: dict[str, int] = {}
        for r in self._records:
            phase_dist[r.experiment_phase.value] = phase_dist.get(r.experiment_phase.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "phase_distribution": phase_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("experiment_lifecycle_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def compute_acceptance_rate(self, domain: ExperimentDomain | None = None) -> dict[str, Any]:
        """Compute acceptance rate overall or filtered by domain."""
        recs = self._records
        if domain is not None:
            recs = [r for r in recs if r.experiment_domain == domain]
        accepted = sum(1 for r in recs if r.experiment_phase == ExperimentPhase.ACCEPTED)
        terminal = sum(
            1
            for r in recs
            if r.experiment_phase in (ExperimentPhase.ACCEPTED, ExperimentPhase.REJECTED)
        )
        rate = round(accepted / terminal, 4) if terminal > 0 else 0.0
        return {
            "domain": domain.value if domain else "all",
            "accepted": accepted,
            "rejected": terminal - accepted,
            "total_terminal": terminal,
            "acceptance_rate": rate,
        }

    def identify_diminishing_returns(self) -> list[dict[str, Any]]:
        """Detect experiments where improvements are plateauing."""
        exp_recs: dict[str, list[ExperimentLifecycleRecord]] = {}
        for r in self._records:
            exp_recs.setdefault(r.experiment_id, []).append(r)
        results: list[dict[str, Any]] = []
        for eid, recs in exp_recs.items():
            improvements = [r.improvement_pct for r in recs if r.improvement_pct != 0.0]
            if len(improvements) < 4:
                continue
            mid = len(improvements) // 2
            first_half = improvements[:mid]
            second_half = improvements[mid:]
            avg_first = sum(first_half) / len(first_half)
            avg_second = sum(second_half) / len(second_half)
            if avg_second < avg_first * 0.5:
                results.append(
                    {
                        "experiment_id": eid,
                        "avg_early_improvement": round(avg_first, 4),
                        "avg_late_improvement": round(avg_second, 4),
                        "decline_ratio": round(avg_second / avg_first, 4) if avg_first > 0 else 0.0,
                        "total_iterations": len(improvements),
                    }
                )
        results.sort(
            key=lambda x: x.get("decline_ratio", 1.0),
        )
        return results

    def recommend_experiment_focus(self) -> list[dict[str, Any]]:
        """Suggest which domains to focus on next based on past results."""
        domain_stats: dict[str, dict[str, Any]] = {}
        for r in self._records:
            d = r.experiment_domain.value
            if d not in domain_stats:
                domain_stats[d] = {
                    "total": 0,
                    "accepted": 0,
                    "improvements": [],
                }
            domain_stats[d]["total"] += 1
            if r.experiment_phase == ExperimentPhase.ACCEPTED:
                domain_stats[d]["accepted"] += 1
            if r.improvement_pct > 0:
                domain_stats[d]["improvements"].append(r.improvement_pct)
        results: list[dict[str, Any]] = []
        for domain, stats in domain_stats.items():
            imps = stats["improvements"]
            avg_imp = round(sum(imps) / len(imps), 4) if imps else 0.0
            acc_rate = round(stats["accepted"] / stats["total"], 4) if stats["total"] > 0 else 0.0
            # Score: high acceptance + high improvement = good focus area
            score = round(acc_rate * 0.4 + min(avg_imp / 100.0, 1.0) * 0.6, 4)
            results.append(
                {
                    "domain": domain,
                    "total_experiments": stats["total"],
                    "acceptance_rate": acc_rate,
                    "avg_improvement_pct": avg_imp,
                    "focus_score": score,
                    "recommendation": "high_priority"
                    if score > 0.5
                    else "medium_priority"
                    if score > 0.2
                    else "low_priority",
                }
            )
        results.sort(key=lambda x: x["focus_score"], reverse=True)
        return results
