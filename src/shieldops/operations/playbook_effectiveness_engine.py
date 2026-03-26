"""Playbook Effectiveness Engine — track SOAR playbook effectiveness."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PlaybookOutcome(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    TIMEOUT = "timeout"


class EffectivenessMetric(StrEnum):
    RESOLUTION_RATE = "resolution_rate"
    SPEED = "speed"
    ACCURACY = "accuracy"
    COVERAGE = "coverage"


class ImprovementAction(StrEnum):
    TUNE = "tune"
    REPLACE = "replace"
    MERGE = "merge"
    DEPRECATE = "deprecate"


# --- Models ---


class PlaybookEffectivenessRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    playbook_outcome: PlaybookOutcome = PlaybookOutcome.SUCCESS
    effectiveness_metric: EffectivenessMetric = EffectivenessMetric.RESOLUTION_RATE
    improvement_action: ImprovementAction = ImprovementAction.TUNE
    score: float = 0.0
    execution_time_s: float = 0.0
    playbook_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class PlaybookEffectivenessAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    playbook_outcome: PlaybookOutcome = PlaybookOutcome.SUCCESS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PlaybookEffectivenessReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_playbook_outcome: dict[str, int] = Field(default_factory=dict)
    by_effectiveness_metric: dict[str, int] = Field(default_factory=dict)
    by_improvement_action: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class PlaybookEffectivenessEngine:
    """Track SOAR playbook effectiveness."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[PlaybookEffectivenessRecord] = []
        self._analyses: list[PlaybookEffectivenessAnalysis] = []
        logger.info(
            "playbook_effectiveness.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ---

    def add_record(
        self,
        name: str,
        playbook_outcome: PlaybookOutcome = (PlaybookOutcome.SUCCESS),
        effectiveness_metric: (EffectivenessMetric) = EffectivenessMetric.RESOLUTION_RATE,
        improvement_action: ImprovementAction = (ImprovementAction.TUNE),
        score: float = 0.0,
        execution_time_s: float = 0.0,
        playbook_id: str = "",
        service: str = "",
        team: str = "",
    ) -> PlaybookEffectivenessRecord:
        record = PlaybookEffectivenessRecord(
            name=name,
            playbook_outcome=playbook_outcome,
            effectiveness_metric=(effectiveness_metric),
            improvement_action=improvement_action,
            score=score,
            execution_time_s=execution_time_s,
            playbook_id=playbook_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "playbook_effectiveness.record_added",
            record_id=record.id,
            name=name,
            outcome=playbook_outcome.value,
        )
        return record

    def get_record(self, record_id: str) -> PlaybookEffectivenessRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        playbook_outcome: (PlaybookOutcome | None) = None,
        effectiveness_metric: (EffectivenessMetric | None) = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[PlaybookEffectivenessRecord]:
        results = list(self._records)
        if playbook_outcome is not None:
            results = [r for r in results if r.playbook_outcome == playbook_outcome]
        if effectiveness_metric is not None:
            results = [r for r in results if r.effectiveness_metric == effectiveness_metric]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        playbook_outcome: PlaybookOutcome = (PlaybookOutcome.SUCCESS),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> PlaybookEffectivenessAnalysis:
        analysis = PlaybookEffectivenessAnalysis(
            name=name,
            playbook_outcome=playbook_outcome,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "playbook_effectiveness.analysis",
            name=name,
            outcome=playbook_outcome.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ---

    def track_execution(
        self,
    ) -> list[dict[str, Any]]:
        """Track playbook execution outcomes."""
        pb_data: dict[
            str,
            list[PlaybookEffectivenessRecord],
        ] = {}
        for r in self._records:
            if r.playbook_id:
                pb_data.setdefault(r.playbook_id, []).append(r)
        results: list[dict[str, Any]] = []
        for pid, records in pb_data.items():
            total = len(records)
            success = sum(1 for r in records if r.playbook_outcome == PlaybookOutcome.SUCCESS)
            times = [r.execution_time_s for r in records]
            avg_time = round(sum(times) / len(times), 2)
            results.append(
                {
                    "playbook_id": pid,
                    "executions": total,
                    "success_rate": round(success / total * 100, 1),
                    "avg_time_s": avg_time,
                    "failure_count": total - success,
                }
            )
        return sorted(
            results,
            key=lambda x: x["success_rate"],
        )

    def measure_effectiveness(
        self,
    ) -> list[dict[str, Any]]:
        """Measure effectiveness by playbook."""
        pb_data: dict[
            str,
            list[PlaybookEffectivenessRecord],
        ] = {}
        for r in self._records:
            if r.playbook_id:
                pb_data.setdefault(r.playbook_id, []).append(r)
        results: list[dict[str, Any]] = []
        for pid, records in pb_data.items():
            scores = [r.score for r in records]
            avg = round(sum(scores) / len(scores), 2)
            outcomes: dict[str, int] = {}
            for r in records:
                o = r.playbook_outcome.value
                outcomes[o] = outcomes.get(o, 0) + 1
            results.append(
                {
                    "playbook_id": pid,
                    "avg_score": avg,
                    "outcome_distribution": outcomes,
                    "effective": avg >= 70,
                    "recommendation": (
                        "maintain" if avg >= 70 else ("tune" if avg >= 40 else "replace")
                    ),
                }
            )
        return sorted(results, key=lambda x: x["avg_score"])

    def recommend_improvements(
        self,
    ) -> list[dict[str, Any]]:
        """Recommend playbook improvements."""
        pb_data: dict[
            str,
            list[PlaybookEffectivenessRecord],
        ] = {}
        for r in self._records:
            if r.playbook_id:
                pb_data.setdefault(r.playbook_id, []).append(r)
        recs: list[dict[str, Any]] = []
        for pid, records in pb_data.items():
            scores = [r.score for r in records]
            avg = round(sum(scores) / len(scores), 2)
            fail_ct = sum(
                1
                for r in records
                if r.playbook_outcome
                in (
                    PlaybookOutcome.FAILURE,
                    PlaybookOutcome.TIMEOUT,
                )
            )
            total = len(records)
            fail_pct = round(fail_ct / total * 100, 1)
            if avg < 50 or fail_pct > 30:
                action = (
                    ImprovementAction.REPLACE
                    if avg < 30
                    else (ImprovementAction.TUNE if avg < 60 else (ImprovementAction.MERGE))
                )
                recs.append(
                    {
                        "playbook_id": pid,
                        "avg_score": avg,
                        "failure_pct": fail_pct,
                        "action": action.value,
                        "reason": ("Low effectiveness" if avg < 50 else "High failure rate"),
                    }
                )
        return sorted(recs, key=lambda x: x["avg_score"])

    # -- standard methods ---

    def analyze_distribution(
        self,
    ) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.playbook_outcome.value
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
                        "playbook_outcome": (r.playbook_outcome.value),
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc: dict[str, list[float]] = {}
        for r in self._records:
            svc.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for s, scores in svc.items():
            results.append(
                {
                    "service": s,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
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

    # -- report / stats ---

    def generate_report(
        self,
    ) -> PlaybookEffectivenessReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            k1 = r.playbook_outcome.value
            by_e1[k1] = by_e1.get(k1, 0) + 1
            k2 = r.effectiveness_metric.value
            by_e2[k2] = by_e2.get(k2, 0) + 1
            k3 = r.improvement_action.value
            by_e3[k3] = by_e3.get(k3, 0) + 1
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
            recs.append("Playbook Effectiveness healthy")
        return PlaybookEffectivenessReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_playbook_outcome=by_e1,
            by_effectiveness_metric=by_e2,
            by_improvement_action=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("playbook_effectiveness.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.playbook_outcome.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "playbook_outcome_dist": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
