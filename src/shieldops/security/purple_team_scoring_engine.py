"""Purple Team Scoring Engine — score red/blue exercises."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TeamRole(StrEnum):
    RED = "red"
    BLUE = "blue"
    PURPLE = "purple"
    WHITE = "white"


class ScoringCriteria(StrEnum):
    DETECTION_RATE = "detection_rate"
    RESPONSE_TIME = "response_time"
    EVASION_SUCCESS = "evasion_success"
    CONTAINMENT = "containment"
    COVERAGE = "coverage"


class ExerciseMaturity(StrEnum):
    INITIAL = "initial"
    DEVELOPING = "developing"
    DEFINED = "defined"
    MANAGED = "managed"
    OPTIMIZING = "optimizing"


# --- Models ---


class ScoringRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    exercise_name: str = ""
    team_role: TeamRole = TeamRole.PURPLE
    criteria: ScoringCriteria = ScoringCriteria.DETECTION_RATE
    maturity: ExerciseMaturity = ExerciseMaturity.INITIAL
    score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ScoringAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    exercise_name: str = ""
    criteria: ScoringCriteria = ScoringCriteria.DETECTION_RATE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ScoringReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_score: float = 0.0
    by_role: dict[str, int] = Field(default_factory=dict)
    by_criteria: dict[str, int] = Field(default_factory=dict)
    by_maturity: dict[str, int] = Field(default_factory=dict)
    low_scores: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class PurpleTeamScoringEngine:
    """Score and compare red/blue team exercises."""

    def __init__(
        self,
        max_records: int = 200000,
        score_threshold: float = 70.0,
    ) -> None:
        self._max = max_records
        self._score_threshold = score_threshold
        self._records: list[ScoringRecord] = []
        self._analyses: list[ScoringAnalysis] = []
        logger.info(
            "purple_team_scoring_engine.initialized",
            max_records=max_records,
        )

    def add_record(
        self,
        exercise_name: str = "",
        team_role: TeamRole = TeamRole.PURPLE,
        criteria: ScoringCriteria = (ScoringCriteria.DETECTION_RATE),
        maturity: ExerciseMaturity = (ExerciseMaturity.INITIAL),
        score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> ScoringRecord:
        rec = ScoringRecord(
            exercise_name=exercise_name,
            team_role=team_role,
            criteria=criteria,
            maturity=maturity,
            score=score,
            service=service,
            team=team,
        )
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "purple_team_scoring.record_added",
            record_id=rec.id,
        )
        return rec

    def process(self, key: str) -> ScoringAnalysis:
        matches = [r for r in self._records if r.exercise_name == key]
        total = sum(r.score for r in matches)
        avg = total / len(matches) if matches else 0.0
        analysis = ScoringAnalysis(
            exercise_name=key,
            analysis_score=round(avg, 2),
            threshold=self._score_threshold,
            breached=avg < self._score_threshold,
            description=f"Scored {len(matches)} entries",
        )
        self._analyses.append(analysis)
        return analysis

    # -- domain methods ---

    def score_team(
        self,
        role: TeamRole = TeamRole.RED,
    ) -> dict[str, Any]:
        """Average score for a given team role."""
        matches = [r for r in self._records if r.team_role == role]
        if not matches:
            return {"role": role.value, "avg": 0.0}
        avg = sum(r.score for r in matches) / len(matches)
        return {
            "role": role.value,
            "count": len(matches),
            "avg_score": round(avg, 2),
        }

    def compare_red_blue(self) -> dict[str, Any]:
        """Compare red vs blue team avg scores."""
        red = self.score_team(TeamRole.RED)
        blue = self.score_team(TeamRole.BLUE)
        return {
            "red": red,
            "blue": blue,
            "delta": round(
                red.get("avg_score", 0.0) - blue.get("avg_score", 0.0),
                2,
            ),
        }

    def track_improvement(self) -> dict[str, Any]:
        """Split-half trend on analysis scores."""
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data"}
        vals = [a.analysis_score for a in self._analyses]
        mid = len(vals) // 2
        first = sum(vals[:mid]) / mid
        second = sum(vals[mid:]) / len(vals[mid:])
        delta = round(second - first, 2)
        if abs(delta) < 5.0:
            trend = "stable"
        elif delta > 0:
            trend = "improving"
        else:
            trend = "degrading"
        return {
            "trend": trend,
            "delta": delta,
            "first_half_avg": round(first, 2),
            "second_half_avg": round(second, 2),
        }

    # -- report / stats ---

    def generate_report(self) -> ScoringReport:
        by_role: dict[str, int] = {}
        by_criteria: dict[str, int] = {}
        by_maturity: dict[str, int] = {}
        for r in self._records:
            rl = r.team_role.value
            by_role[rl] = by_role.get(rl, 0) + 1
            cr = r.criteria.value
            by_criteria[cr] = by_criteria.get(cr, 0) + 1
            mt = r.maturity.value
            by_maturity[mt] = by_maturity.get(mt, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        low = [r.exercise_name for r in self._records if r.score < self._score_threshold][:5]
        recs: list[str] = []
        if low:
            recs.append(f"{len(low)} exercise(s) below score threshold")
        if not recs:
            recs.append("Team scoring is healthy")
        return ScoringReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_score=avg,
            by_role=by_role,
            by_criteria=by_criteria,
            by_maturity=by_maturity,
            low_scores=low,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.team_role.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "score_threshold": self._score_threshold,
            "role_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("purple_team_scoring_engine.cleared")
        return {"status": "cleared"}
