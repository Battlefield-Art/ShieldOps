"""AutonomousExperimentEngine — Fully autonomous experiment lifecycle with budget enforcement."""

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
    HYPOTHESIS = "hypothesis"
    DESIGN = "design"
    EXECUTE = "execute"
    ANALYZE = "analyze"
    DECIDE = "decide"


class BudgetStatus(StrEnum):
    UNDER_BUDGET = "under_budget"
    AT_LIMIT = "at_limit"
    OVER_BUDGET = "over_budget"
    EXHAUSTED = "exhausted"


class DecisionOutcome(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    EXTEND = "extend"
    PIVOT = "pivot"


# --- Models ---


class AutonomousExperimentRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    experiment_phase: ExperimentPhase = ExperimentPhase.HYPOTHESIS
    budget_status: BudgetStatus = BudgetStatus.UNDER_BUDGET
    decision_outcome: DecisionOutcome = DecisionOutcome.ACCEPT
    score: float = 0.0
    budget_spent: float = 0.0
    budget_total: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AutonomousExperimentAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    experiment_phase: ExperimentPhase = ExperimentPhase.HYPOTHESIS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AutonomousExperimentReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_experiment_phase: dict[str, int] = Field(default_factory=dict)
    by_budget_status: dict[str, int] = Field(default_factory=dict)
    by_decision_outcome: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AutonomousExperimentEngine:
    """Fully autonomous experiment lifecycle with budget enforcement."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AutonomousExperimentRecord] = []
        self._analyses: list[AutonomousExperimentAnalysis] = []
        logger.info(
            "autonomous_experiment_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        experiment_phase: ExperimentPhase = ExperimentPhase.HYPOTHESIS,
        budget_status: BudgetStatus = BudgetStatus.UNDER_BUDGET,
        decision_outcome: DecisionOutcome = DecisionOutcome.ACCEPT,
        score: float = 0.0,
        budget_spent: float = 0.0,
        budget_total: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> AutonomousExperimentRecord:
        record = AutonomousExperimentRecord(
            name=name,
            experiment_phase=experiment_phase,
            budget_status=budget_status,
            decision_outcome=decision_outcome,
            score=score,
            budget_spent=budget_spent,
            budget_total=budget_total,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "autonomous_experiment_engine.record_added",
            record_id=record.id,
            name=name,
            experiment_phase=experiment_phase.value,
            budget_status=budget_status.value,
        )
        return record

    def get_record(self, record_id: str) -> AutonomousExperimentRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        experiment_phase: ExperimentPhase | None = None,
        budget_status: BudgetStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AutonomousExperimentRecord]:
        results = list(self._records)
        if experiment_phase is not None:
            results = [r for r in results if r.experiment_phase == experiment_phase]
        if budget_status is not None:
            results = [r for r in results if r.budget_status == budget_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        experiment_phase: ExperimentPhase = ExperimentPhase.HYPOTHESIS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AutonomousExperimentAnalysis:
        analysis = AutonomousExperimentAnalysis(
            name=name,
            experiment_phase=experiment_phase,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "autonomous_experiment_engine.analysis_added",
            name=name,
            experiment_phase=experiment_phase.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def generate_experiment_hypotheses(self) -> list[dict[str, Any]]:
        """Generate hypotheses based on past experiment outcomes."""
        outcome_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            svc = r.service
            outcome_data.setdefault(svc, {})
            o = r.decision_outcome.value
            outcome_data[svc][o] = outcome_data[svc].get(o, 0) + 1
        hypotheses: list[dict[str, Any]] = []
        for svc, outcomes in outcome_data.items():
            total = sum(outcomes.values())
            accepted = outcomes.get("accept", 0)
            rejected = outcomes.get("reject", 0)
            pivoted = outcomes.get("pivot", 0)
            if rejected > accepted:
                hypotheses.append(
                    {
                        "service": svc,
                        "hypothesis": f"Service {svc} needs fundamentally different approach",
                        "basis": f"{rejected}/{total} experiments rejected",
                        "confidence": round(rejected / total * 100, 1) if total else 0.0,
                        "priority": "high",
                    }
                )
            if pivoted > 0:
                hypotheses.append(
                    {
                        "service": svc,
                        "hypothesis": f"Service {svc} experiments need better scoping",
                        "basis": f"{pivoted}/{total} experiments pivoted",
                        "confidence": round(pivoted / total * 100, 1) if total else 0.0,
                        "priority": "medium",
                    }
                )
        return sorted(hypotheses, key=lambda x: x["confidence"], reverse=True)

    def enforce_budget_constraints(self) -> list[dict[str, Any]]:
        """Identify experiments that are over budget or at risk."""
        violations: list[dict[str, Any]] = []
        for r in self._records:
            if r.budget_status in (BudgetStatus.OVER_BUDGET, BudgetStatus.EXHAUSTED):
                utilization = (
                    round(r.budget_spent / r.budget_total * 100, 1) if r.budget_total > 0 else 0.0
                )
                violations.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "budget_status": r.budget_status.value,
                        "budget_spent": r.budget_spent,
                        "budget_total": r.budget_total,
                        "utilization_pct": utilization,
                        "action": "halt" if r.budget_status == BudgetStatus.EXHAUSTED else "review",
                        "severity": "critical"
                        if r.budget_status == BudgetStatus.EXHAUSTED
                        else "high",
                    }
                )
        at_limit = [r for r in self._records if r.budget_status == BudgetStatus.AT_LIMIT]
        for r in at_limit:
            utilization = (
                round(r.budget_spent / r.budget_total * 100, 1) if r.budget_total > 0 else 0.0
            )
            violations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "budget_status": r.budget_status.value,
                    "budget_spent": r.budget_spent,
                    "budget_total": r.budget_total,
                    "utilization_pct": utilization,
                    "action": "monitor",
                    "severity": "warning",
                }
            )
        severity_order = {"critical": 0, "high": 1, "warning": 2}
        return sorted(violations, key=lambda x: severity_order.get(x["severity"], 3))

    def compute_experiment_roi(self) -> list[dict[str, Any]]:
        """Compute ROI per experiment by comparing score vs budget spent."""
        svc_data: dict[str, list[AutonomousExperimentRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            total_spent = sum(r.budget_spent for r in records)
            avg_score = round(sum(r.score for r in records) / len(records), 2) if records else 0.0
            accepted = sum(1 for r in records if r.decision_outcome == DecisionOutcome.ACCEPT)
            roi = round(avg_score / total_spent, 4) if total_spent > 0 else 0.0
            results.append(
                {
                    "service": svc,
                    "total_experiments": len(records),
                    "total_budget_spent": round(total_spent, 2),
                    "avg_score": avg_score,
                    "accepted_count": accepted,
                    "acceptance_rate": round(accepted / len(records) * 100, 1) if records else 0.0,
                    "roi": roi,
                }
            )
        return sorted(results, key=lambda x: x["roi"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.experiment_phase.value
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
                        "experiment_phase": r.experiment_phase.value,
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

    def generate_report(self) -> AutonomousExperimentReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.experiment_phase.value] = by_e1.get(r.experiment_phase.value, 0) + 1
            by_e2[r.budget_status.value] = by_e2.get(r.budget_status.value, 0) + 1
            by_e3[r.decision_outcome.value] = by_e3.get(r.decision_outcome.value, 0) + 1
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
            recs.append("Autonomous Experiment Engine is healthy")
        return AutonomousExperimentReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_experiment_phase=by_e1,
            by_budget_status=by_e2,
            by_decision_outcome=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("autonomous_experiment_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.experiment_phase.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "experiment_phase_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
