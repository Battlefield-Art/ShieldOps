"""PostureValidationEngine — Validates security posture via digital twin comparisons."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PostureCategory(StrEnum):
    NETWORK = "network"
    IDENTITY = "identity"
    DATA = "data"
    APPLICATION = "application"


class ValidationMethod(StrEnum):
    SIMULATION = "simulation"
    COMPARISON = "comparison"
    BENCHMARK = "benchmark"
    ADVERSARIAL = "adversarial"


class PostureGrade(StrEnum):
    A_PLUS = "a_plus"
    A = "a"
    B = "b"
    C = "c"
    D = "d"
    F = "f"


# --- Models ---


class PostureRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource_id: str = ""
    category: PostureCategory = PostureCategory.NETWORK
    validation_method: ValidationMethod = ValidationMethod.BENCHMARK
    posture_grade: PostureGrade = PostureGrade.C
    score: float = 0.0
    baseline_score: float = 0.0
    drift_pct: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class PostureAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: PostureCategory = PostureCategory.NETWORK
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PostureReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_posture_category: dict[str, int] = Field(default_factory=dict)
    by_validation_method: dict[str, int] = Field(default_factory=dict)
    by_posture_grade: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class PostureValidationEngine:
    """Validates security posture via digital twin comparisons."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[PostureRecord] = []
        self._analyses: list[PostureAnalysis] = []
        logger.info(
            "posture_validation_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        resource_id: str,
        category: PostureCategory = PostureCategory.NETWORK,
        validation_method: ValidationMethod = ValidationMethod.BENCHMARK,
        posture_grade: PostureGrade = PostureGrade.C,
        score: float = 0.0,
        baseline_score: float = 0.0,
        drift_pct: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> PostureRecord:
        record = PostureRecord(
            resource_id=resource_id,
            category=category,
            validation_method=validation_method,
            posture_grade=posture_grade,
            score=score,
            baseline_score=baseline_score,
            drift_pct=drift_pct,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "posture_validation_engine.record_added",
            record_id=record.id,
            resource_id=resource_id,
            category=category.value,
            posture_grade=posture_grade.value,
        )
        return record

    def get_record(self, record_id: str) -> PostureRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        category: PostureCategory | None = None,
        validation_method: ValidationMethod | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[PostureRecord]:
        results = list(self._records)
        if category is not None:
            results = [r for r in results if r.category == category]
        if validation_method is not None:
            results = [r for r in results if r.validation_method == validation_method]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        category: PostureCategory = PostureCategory.NETWORK,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> PostureAnalysis:
        analysis = PostureAnalysis(
            name=name,
            category=category,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "posture_validation_engine.analysis_added",
            name=name,
            category=category.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compare_baseline(self) -> list[dict[str, Any]]:
        """Compare current posture scores against baseline for each resource."""
        resource_data: dict[str, list[PostureRecord]] = {}
        for r in self._records:
            resource_data.setdefault(r.resource_id, []).append(r)
        results: list[dict[str, Any]] = []
        for resource_id, records in resource_data.items():
            scores = [r.score for r in records]
            baselines = [r.baseline_score for r in records if r.baseline_score > 0]
            avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
            avg_baseline = round(sum(baselines) / len(baselines), 2) if baselines else 0.0
            drift = round(avg_score - avg_baseline, 2) if avg_baseline else 0.0
            drifted_records = [r for r in records if abs(r.drift_pct) > 10]
            results.append(
                {
                    "resource_id": resource_id,
                    "current_avg_score": avg_score,
                    "baseline_avg_score": avg_baseline,
                    "drift": drift,
                    "drift_direction": "improved"
                    if drift > 0
                    else ("degraded" if drift < 0 else "stable"),
                    "drifted_assessments": len(drifted_records),
                    "categories_assessed": sorted({r.category.value for r in records}),
                }
            )
        return sorted(results, key=lambda x: x["drift"])

    def score_posture(self) -> list[dict[str, Any]]:
        """Score overall security posture per category."""
        grade_scores = {
            PostureGrade.A_PLUS: 100,
            PostureGrade.A: 90,
            PostureGrade.B: 80,
            PostureGrade.C: 70,
            PostureGrade.D: 60,
            PostureGrade.F: 40,
        }
        category_data: dict[str, list[PostureRecord]] = {}
        for r in self._records:
            category_data.setdefault(r.category.value, []).append(r)
        results: list[dict[str, Any]] = []
        for category, records in category_data.items():
            scores = [r.score for r in records]
            avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
            grade_vals = [grade_scores.get(r.posture_grade, 50) for r in records]
            avg_grade_val = round(sum(grade_vals) / len(grade_vals), 2) if grade_vals else 0.0
            # Determine overall grade
            overall_grade = PostureGrade.F
            for grade, val in sorted(grade_scores.items(), key=lambda x: x[1], reverse=True):
                if avg_grade_val >= val:
                    overall_grade = grade
                    break
            results.append(
                {
                    "category": category,
                    "resources_assessed": len({r.resource_id for r in records}),
                    "avg_score": avg_score,
                    "overall_grade": overall_grade.value,
                    "avg_grade_value": avg_grade_val,
                    "grade_distribution": {
                        g.value: sum(1 for r in records if r.posture_grade == g)
                        for g in PostureGrade
                        if any(r.posture_grade == g for r in records)
                    },
                }
            )
        return sorted(results, key=lambda x: x["avg_score"])

    def identify_hardening_opportunities(self) -> list[dict[str, Any]]:
        """Identify resources and categories with hardening opportunities."""
        weak_grades = {PostureGrade.C, PostureGrade.D, PostureGrade.F}
        opportunities: list[dict[str, Any]] = []
        resource_data: dict[str, list[PostureRecord]] = {}
        for r in self._records:
            resource_data.setdefault(r.resource_id, []).append(r)
        for resource_id, records in resource_data.items():
            weak = [r for r in records if r.posture_grade in weak_grades]
            if not weak:
                continue
            categories_needing_hardening = sorted({r.category.value for r in weak})
            scores = [r.score for r in weak]
            avg_weak_score = round(sum(scores) / len(scores), 2) if scores else 0.0
            priority = (
                "critical"
                if any(r.posture_grade == PostureGrade.F for r in weak)
                else ("high" if any(r.posture_grade == PostureGrade.D for r in weak) else "medium")
            )
            opportunities.append(
                {
                    "resource_id": resource_id,
                    "weak_assessments": len(weak),
                    "categories_to_harden": categories_needing_hardening,
                    "avg_weak_score": avg_weak_score,
                    "worst_grade": min(
                        (r.posture_grade for r in weak),
                        key=lambda g: list(PostureGrade).index(g),
                    ).value,
                    "priority": priority,
                    "recommendation": (
                        f"Harden {', '.join(categories_needing_hardening)} for {resource_id}"
                    ),
                }
            )
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        return sorted(opportunities, key=lambda x: priority_order.get(x["priority"], 99))

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.category.value
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
                        "resource_id": r.resource_id,
                        "category": r.category.value,
                        "posture_grade": r.posture_grade.value,
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

    def process(self, resource_id: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.resource_id == resource_id]
        if not matched:
            return {"key": resource_id, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": resource_id,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> PostureReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.category.value] = by_e1.get(r.category.value, 0) + 1
            by_e2[r.validation_method.value] = by_e2.get(r.validation_method.value, 0) + 1
            by_e3[r.posture_grade.value] = by_e3.get(r.posture_grade.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["resource_id"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Posture Validation Engine is healthy")
        return PostureReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_posture_category=by_e1,
            by_validation_method=by_e2,
            by_posture_grade=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("posture_validation_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.category.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "posture_category_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
