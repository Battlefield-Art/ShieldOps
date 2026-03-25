"""Adversarial Effectiveness Engine — track red/blue validation effectiveness."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ValidationOutcome(StrEnum):
    BLOCKED = "blocked"
    DETECTED = "detected"
    BYPASSED = "bypassed"
    INCONCLUSIVE = "inconclusive"
    REGRESSION = "regression"


class DefenseCategory(StrEnum):
    FIREWALL = "firewall"
    POLICY = "policy"
    CREDENTIAL = "credential"
    CONFIG = "config"
    DETECTION = "detection"


class TrendDirection(StrEnum):
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    VOLATILE = "volatile"
    NEW = "new"


# --- Models ---


class AdversarialEffectivenessRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    validation_id: str = ""
    validation_outcome: ValidationOutcome = ValidationOutcome.BLOCKED
    defense_category: DefenseCategory = DefenseCategory.FIREWALL
    trend_direction: TrendDirection = TrendDirection.STABLE
    technique_id: str = ""
    effectiveness_pct: float = 0.0
    regression: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AdversarialEffectivenessAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    validation_id: str = ""
    defense_category: DefenseCategory = DefenseCategory.FIREWALL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AdversarialEffectivenessReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_validation_outcome: dict[str, int] = Field(default_factory=dict)
    by_defense_category: dict[str, int] = Field(default_factory=dict)
    by_trend_direction: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AdversarialEffectivenessEngine:
    """Track red/blue validation effectiveness across defense categories."""

    def __init__(
        self,
        max_records: int = 200000,
        effectiveness_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = effectiveness_threshold
        self._records: list[AdversarialEffectivenessRecord] = []
        self._analyses: list[AdversarialEffectivenessAnalysis] = []
        logger.info(
            "adversarial_effectiveness_engine.initialized",
            max_records=max_records,
            effectiveness_threshold=effectiveness_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        validation_id: str,
        validation_outcome: ValidationOutcome = ValidationOutcome.BLOCKED,
        defense_category: DefenseCategory = DefenseCategory.FIREWALL,
        trend_direction: TrendDirection = TrendDirection.STABLE,
        technique_id: str = "",
        effectiveness_pct: float = 0.0,
        regression: bool = False,
        service: str = "",
        team: str = "",
    ) -> AdversarialEffectivenessRecord:
        record = AdversarialEffectivenessRecord(
            validation_id=validation_id,
            validation_outcome=validation_outcome,
            defense_category=defense_category,
            trend_direction=trend_direction,
            technique_id=technique_id,
            effectiveness_pct=effectiveness_pct,
            regression=regression,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "adversarial_effectiveness_engine.record_added",
            record_id=record.id,
            validation_id=validation_id,
            validation_outcome=validation_outcome.value,
            defense_category=defense_category.value,
        )
        return record

    def get_record(self, record_id: str) -> AdversarialEffectivenessRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        validation_outcome: ValidationOutcome | None = None,
        defense_category: DefenseCategory | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AdversarialEffectivenessRecord]:
        results = list(self._records)
        if validation_outcome is not None:
            results = [r for r in results if r.validation_outcome == validation_outcome]
        if defense_category is not None:
            results = [r for r in results if r.defense_category == defense_category]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        validation_id: str,
        defense_category: DefenseCategory = DefenseCategory.FIREWALL,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AdversarialEffectivenessAnalysis:
        analysis = AdversarialEffectivenessAnalysis(
            validation_id=validation_id,
            defense_category=defense_category,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "adversarial_effectiveness_engine.analysis_added",
            validation_id=validation_id,
            defense_category=defense_category.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_defense_effectiveness(self) -> list[dict[str, Any]]:
        """Analyze effectiveness per defense category."""
        cat_data: dict[str, list[float]] = {}
        for r in self._records:
            cat_data.setdefault(r.defense_category.value, []).append(r.effectiveness_pct)
        results: list[dict[str, Any]] = []
        for cat, scores in cat_data.items():
            avg = round(sum(scores) / len(scores), 2) if scores else 0.0
            blocked = sum(
                1
                for r in self._records
                if r.defense_category.value == cat
                and r.validation_outcome in (ValidationOutcome.BLOCKED, ValidationOutcome.DETECTED)
            )
            results.append(
                {
                    "defense_category": cat,
                    "count": len(scores),
                    "avg_effectiveness": avg,
                    "blocked_or_detected": blocked,
                    "below_threshold": sum(1 for s in scores if s < self._threshold),
                }
            )
        return sorted(results, key=lambda x: x["avg_effectiveness"])

    def identify_regressions(self) -> list[dict[str, Any]]:
        """Identify defense regressions needing attention."""
        regressions: list[dict[str, Any]] = []
        for r in self._records:
            if r.regression or r.validation_outcome == ValidationOutcome.REGRESSION:
                regressions.append(
                    {
                        "record_id": r.id,
                        "validation_id": r.validation_id,
                        "technique_id": r.technique_id,
                        "defense_category": r.defense_category.value,
                        "effectiveness_pct": r.effectiveness_pct,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(regressions, key=lambda x: x["effectiveness_pct"])

    def detect_effectiveness_trends(self) -> list[dict[str, Any]]:
        """Detect effectiveness trends across defense categories."""
        cat_trends: dict[str, dict[str, int]] = {}
        for r in self._records:
            cat = r.defense_category.value
            cat_trends.setdefault(cat, {})
            td = r.trend_direction.value
            cat_trends[cat][td] = cat_trends[cat].get(td, 0) + 1
        results: list[dict[str, Any]] = []
        for cat, trends in cat_trends.items():
            dominant = max(trends, key=trends.get) if trends else "unknown"  # type: ignore[arg-type]
            results.append(
                {
                    "defense_category": cat,
                    "dominant_trend": dominant,
                    "trend_counts": trends,
                    "degrading_count": trends.get("degrading", 0),
                }
            )
        return sorted(results, key=lambda x: x["degrading_count"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def generate_report(self) -> AdversarialEffectivenessReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.validation_outcome.value] = by_e1.get(r.validation_outcome.value, 0) + 1
            by_e2[r.defense_category.value] = by_e2.get(r.defense_category.value, 0) + 1
            by_e3[r.trend_direction.value] = by_e3.get(r.trend_direction.value, 0) + 1
        scores = [r.effectiveness_pct for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for s in scores if s < self._threshold)
        regressions = self.identify_regressions()
        top_gaps = [o["validation_id"] for o in regressions[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} validation(s) below threshold ({self._threshold})")
        if avg_score < self._threshold:
            recs.append(f"Avg effectiveness {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Adversarial Effectiveness Engine is healthy")
        return AdversarialEffectivenessReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_validation_outcome=by_e1,
            by_defense_category=by_e2,
            by_trend_direction=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("adversarial_effectiveness_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.validation_outcome.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "effectiveness_threshold": self._threshold,
            "validation_outcome_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
