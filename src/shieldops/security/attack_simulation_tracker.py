"""AttackSimulationTracker -- track attack simulations."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SimulationScope(StrEnum):
    ENDPOINT = "endpoint"
    NETWORK = "network"
    IDENTITY = "identity"
    APPLICATION = "application"
    FULL_CHAIN = "full_chain"


class OutcomeCategory(StrEnum):
    BLOCKED = "blocked"
    DETECTED = "detected"
    MISSED = "missed"
    PARTIAL = "partial"


class LessonLearned(StrEnum):
    RULE_GAP = "rule_gap"
    CONFIG_ISSUE = "config_issue"
    PROCESS_GAP = "process_gap"
    TOOL_LIMITATION = "tool_limitation"
    NO_ISSUE = "no_issue"


# --- Models ---


class AttackSimulationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    scope: SimulationScope = SimulationScope.ENDPOINT
    outcome: OutcomeCategory = OutcomeCategory.MISSED
    lesson: LessonLearned = LessonLearned.NO_ISSUE
    score: float = 0.0
    technique_id: str = ""
    campaign: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AttackSimulationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    scope: SimulationScope = SimulationScope.ENDPOINT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AttackSimulationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_scope: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    by_lesson: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AttackSimulationTracker:
    """Track attack simulation outcomes."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AttackSimulationRecord] = []
        self._analyses: list[AttackSimulationAnalysis] = []
        logger.info(
            "attack_simulation_tracker.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def add_record(
        self,
        name: str,
        scope: SimulationScope = SimulationScope.ENDPOINT,
        outcome: OutcomeCategory = OutcomeCategory.MISSED,
        lesson: LessonLearned = LessonLearned.NO_ISSUE,
        score: float = 0.0,
        technique_id: str = "",
        campaign: str = "",
        service: str = "",
        team: str = "",
    ) -> AttackSimulationRecord:
        record = AttackSimulationRecord(
            name=name,
            scope=scope,
            outcome=outcome,
            lesson=lesson,
            score=score,
            technique_id=technique_id,
            campaign=campaign,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "attack_simulation_tracker.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> AttackSimulationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        scope: SimulationScope | None = None,
        outcome: OutcomeCategory | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AttackSimulationRecord]:
        results = list(self._records)
        if scope is not None:
            results = [r for r in results if r.scope == scope]
        if outcome is not None:
            results = [r for r in results if r.outcome == outcome]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        scope: SimulationScope = SimulationScope.ENDPOINT,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AttackSimulationAnalysis:
        analysis = AttackSimulationAnalysis(
            name=name,
            scope=scope,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ---

    def track_simulation(
        self,
    ) -> list[dict[str, Any]]:
        """Track simulations by scope."""
        scope_data: dict[str, list[AttackSimulationRecord]] = {}
        for r in self._records:
            scope_data.setdefault(r.scope.value, []).append(r)
        results: list[dict[str, Any]] = []
        for scope, records in scope_data.items():
            blocked = sum(1 for r in records if r.outcome == OutcomeCategory.BLOCKED)
            total = len(records)
            results.append(
                {
                    "scope": scope,
                    "total": total,
                    "blocked": blocked,
                    "block_rate_pct": round(blocked / total * 100, 1),
                }
            )
        return sorted(
            results,
            key=lambda x: x["block_rate_pct"],
        )

    def analyze_outcomes(
        self,
    ) -> dict[str, Any]:
        """Analyze outcome distribution."""
        outcome_scores: dict[str, list[float]] = {}
        for r in self._records:
            outcome_scores.setdefault(r.outcome.value, []).append(r.score)
        analysis: dict[str, Any] = {}
        for outcome, scores in outcome_scores.items():
            avg = sum(scores) / len(scores)
            analysis[outcome] = {
                "avg_score": round(avg, 2),
                "count": len(scores),
            }
        return analysis

    def extract_lessons(
        self,
    ) -> list[dict[str, Any]]:
        """Extract lessons from simulations."""
        lesson_data: dict[str, list[AttackSimulationRecord]] = {}
        for r in self._records:
            if r.lesson != LessonLearned.NO_ISSUE:
                lesson_data.setdefault(r.lesson.value, []).append(r)
        results: list[dict[str, Any]] = []
        for lesson, records in lesson_data.items():
            results.append(
                {
                    "lesson": lesson,
                    "count": len(records),
                    "techniques": list({r.technique_id for r in records}),
                    "avg_score": round(
                        sum(r.score for r in records) / len(records),
                        2,
                    ),
                }
            )
        return sorted(
            results,
            key=lambda x: x["count"],
            reverse=True,
        )

    # -- standard methods ---

    def identify_gaps(
        self,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "scope": r.scope.value,
                        "score": r.score,
                        "service": r.service,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.campaign == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    def generate_report(
        self,
    ) -> AttackSimulationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            v1 = r.scope.value
            by_e1[v1] = by_e1.get(v1, 0) + 1
            v2 = r.outcome.value
            by_e2[v2] = by_e2.get(v2, 0) + 1
            v3 = r.lesson.value
            by_e3[v3] = by_e3.get(v3, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Attack Simulation Tracker healthy")
        return AttackSimulationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_scope=by_e1,
            by_outcome=by_e2,
            by_lesson=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("attack_simulation_tracker.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.scope.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "scope_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
