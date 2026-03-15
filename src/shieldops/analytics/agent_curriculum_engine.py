"""AgentCurriculumEngine — progressive learning curriculum for agents."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DifficultyLevel(StrEnum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class LearningObjective(StrEnum):
    ACCURACY = "accuracy"
    SPEED = "speed"
    COST_EFFICIENCY = "cost_efficiency"
    COVERAGE = "coverage"


class CurriculumStatus(StrEnum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    MASTERED = "mastered"
    REGRESSED = "regressed"


# --- Models ---


class AgentCurriculumRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    difficulty_level: DifficultyLevel = DifficultyLevel.BEGINNER
    learning_objective: LearningObjective = LearningObjective.ACCURACY
    curriculum_status: CurriculumStatus = CurriculumStatus.NOT_STARTED
    score: float = 0.0
    mastery_pct: float = 0.0
    agent_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentCurriculumAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    difficulty_level: DifficultyLevel = DifficultyLevel.BEGINNER
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentCurriculumReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_difficulty_level: dict[str, int] = Field(default_factory=dict)
    by_learning_objective: dict[str, int] = Field(default_factory=dict)
    by_curriculum_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentCurriculumEngine:
    """Progressive learning curriculum for agents — determines what to learn next."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AgentCurriculumRecord] = []
        self._analyses: list[AgentCurriculumAnalysis] = []
        logger.info(
            "agent_curriculum_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        difficulty_level: DifficultyLevel = DifficultyLevel.BEGINNER,
        learning_objective: LearningObjective = LearningObjective.ACCURACY,
        curriculum_status: CurriculumStatus = CurriculumStatus.NOT_STARTED,
        score: float = 0.0,
        mastery_pct: float = 0.0,
        agent_id: str = "",
        service: str = "",
        team: str = "",
    ) -> AgentCurriculumRecord:
        record = AgentCurriculumRecord(
            name=name,
            difficulty_level=difficulty_level,
            learning_objective=learning_objective,
            curriculum_status=curriculum_status,
            score=score,
            mastery_pct=mastery_pct,
            agent_id=agent_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_curriculum_engine.record_added",
            record_id=record.id,
            name=name,
            difficulty_level=difficulty_level.value,
            curriculum_status=curriculum_status.value,
        )
        return record

    def get_record(self, record_id: str) -> AgentCurriculumRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        difficulty_level: DifficultyLevel | None = None,
        curriculum_status: CurriculumStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AgentCurriculumRecord]:
        results = list(self._records)
        if difficulty_level is not None:
            results = [r for r in results if r.difficulty_level == difficulty_level]
        if curriculum_status is not None:
            results = [r for r in results if r.curriculum_status == curriculum_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        difficulty_level: DifficultyLevel = DifficultyLevel.BEGINNER,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AgentCurriculumAnalysis:
        analysis = AgentCurriculumAnalysis(
            name=name,
            difficulty_level=difficulty_level,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "agent_curriculum_engine.analysis_added",
            name=name,
            difficulty_level=difficulty_level.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def recommend_next_lesson(self) -> list[dict[str, Any]]:
        """Recommend next lessons for each agent based on curriculum progress."""
        agent_data: dict[str, list[AgentCurriculumRecord]] = {}
        for r in self._records:
            agent_data.setdefault(r.agent_id, []).append(r)
        recommendations: list[dict[str, Any]] = []
        difficulty_order = [
            DifficultyLevel.BEGINNER,
            DifficultyLevel.INTERMEDIATE,
            DifficultyLevel.ADVANCED,
            DifficultyLevel.EXPERT,
        ]
        for agent_id, records in agent_data.items():
            mastered = {r.name for r in records if r.curriculum_status == CurriculumStatus.MASTERED}
            not_mastered = [r for r in records if r.curriculum_status != CurriculumStatus.MASTERED]
            if not not_mastered:
                recommendations.append(
                    {
                        "agent_id": agent_id,
                        "recommendation": "all_mastered",
                        "next_difficulty": "expert",
                        "mastered_count": len(mastered),
                    }
                )
                continue
            # Prioritize: regressed > in_progress > not_started, lower difficulty first
            not_mastered.sort(
                key=lambda r: (
                    0
                    if r.curriculum_status == CurriculumStatus.REGRESSED
                    else (1 if r.curriculum_status == CurriculumStatus.IN_PROGRESS else 2),
                    difficulty_order.index(r.difficulty_level)
                    if r.difficulty_level in difficulty_order
                    else 99,
                )
            )
            next_lesson = not_mastered[0]
            recommendations.append(
                {
                    "agent_id": agent_id,
                    "recommendation": next_lesson.name,
                    "difficulty": next_lesson.difficulty_level.value,
                    "status": next_lesson.curriculum_status.value,
                    "mastery_pct": next_lesson.mastery_pct,
                    "mastered_count": len(mastered),
                }
            )
        return recommendations

    def evaluate_mastery_level(self) -> dict[str, Any]:
        """Evaluate overall mastery level across all agents."""
        status_counts: dict[str, int] = {}
        for r in self._records:
            key = r.curriculum_status.value
            status_counts[key] = status_counts.get(key, 0) + 1
        total = len(self._records)
        if total == 0:
            return {"overall_mastery_pct": 0.0, "status_distribution": {}}
        mastered = status_counts.get("mastered", 0)
        return {
            "overall_mastery_pct": round(mastered / total * 100, 1),
            "total_lessons": total,
            "status_distribution": status_counts,
            "avg_mastery_pct": round(sum(r.mastery_pct for r in self._records) / total, 1),
        }

    def detect_skill_regression(self) -> list[dict[str, Any]]:
        """Detect agents showing skill regression."""
        regressions: list[dict[str, Any]] = []
        agent_data: dict[str, list[AgentCurriculumRecord]] = {}
        for r in self._records:
            agent_data.setdefault(r.agent_id, []).append(r)
        for agent_id, records in agent_data.items():
            regressed = [r for r in records if r.curriculum_status == CurriculumStatus.REGRESSED]
            if regressed:
                regressions.append(
                    {
                        "agent_id": agent_id,
                        "regressed_lessons": [r.name for r in regressed],
                        "regression_count": len(regressed),
                        "total_lessons": len(records),
                        "regression_pct": round(len(regressed) / len(records) * 100, 1),
                        "severity": "high" if len(regressed) > 2 else "moderate",
                    }
                )
        return sorted(regressions, key=lambda x: x["regression_count"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.difficulty_level.value
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
                        "difficulty_level": r.difficulty_level.value,
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

    def generate_report(self) -> AgentCurriculumReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.difficulty_level.value] = by_e1.get(r.difficulty_level.value, 0) + 1
            by_e2[r.learning_objective.value] = by_e2.get(r.learning_objective.value, 0) + 1
            by_e3[r.curriculum_status.value] = by_e3.get(r.curriculum_status.value, 0) + 1
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
            recs.append("Agent Curriculum Engine is healthy")
        return AgentCurriculumReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_difficulty_level=by_e1,
            by_learning_objective=by_e2,
            by_curriculum_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_curriculum_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.difficulty_level.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "difficulty_level_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
