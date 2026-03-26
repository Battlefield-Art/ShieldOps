"""SOCAssistantAnalyticsEngine — Track SOC assistant query effectiveness and knowledge gaps."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class QueryCategory(StrEnum):
    INVESTIGATION = "investigation"
    THREAT_HUNT = "threat_hunt"
    COMPLIANCE = "compliance"
    STATUS = "status"
    EXPLANATION = "explanation"


class ResponseQuality(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    ADEQUATE = "adequate"
    POOR = "poor"


class AnalystSatisfaction(StrEnum):
    VERY_SATISFIED = "very_satisfied"
    SATISFIED = "satisfied"
    NEUTRAL = "neutral"
    DISSATISFIED = "dissatisfied"


# --- Models ---


class AssistantQueryRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    query_category: QueryCategory = QueryCategory.INVESTIGATION
    response_quality: ResponseQuality = ResponseQuality.GOOD
    analyst_satisfaction: AnalystSatisfaction = AnalystSatisfaction.NEUTRAL
    score: float = 0.0
    response_time_ms: float = 0.0
    analyst_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AssistantAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    query_category: QueryCategory = QueryCategory.INVESTIGATION
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AssistantReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_query_category: dict[str, int] = Field(default_factory=dict)
    by_response_quality: dict[str, int] = Field(default_factory=dict)
    by_analyst_satisfaction: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class SOCAssistantAnalyticsEngine:
    """Track SOC assistant query effectiveness and knowledge gaps."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AssistantQueryRecord] = []
        self._analyses: list[AssistantAnalysis] = []
        logger.info(
            "soc_assistant_analytics_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list -----------------------------------

    def add_record(
        self,
        name: str,
        query_category: QueryCategory = QueryCategory.INVESTIGATION,
        response_quality: ResponseQuality = ResponseQuality.GOOD,
        analyst_satisfaction: AnalystSatisfaction = (AnalystSatisfaction.NEUTRAL),
        score: float = 0.0,
        response_time_ms: float = 0.0,
        analyst_id: str = "",
        service: str = "",
        team: str = "",
    ) -> AssistantQueryRecord:
        record = AssistantQueryRecord(
            name=name,
            query_category=query_category,
            response_quality=response_quality,
            analyst_satisfaction=analyst_satisfaction,
            score=score,
            response_time_ms=response_time_ms,
            analyst_id=analyst_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "soc_assistant_analytics_engine.record_added",
            record_id=record.id,
            name=name,
            query_category=query_category.value,
            response_quality=response_quality.value,
        )
        return record

    def get_record(self, record_id: str) -> AssistantQueryRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        query_category: QueryCategory | None = None,
        response_quality: ResponseQuality | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AssistantQueryRecord]:
        results = list(self._records)
        if query_category is not None:
            results = [r for r in results if r.query_category == query_category]
        if response_quality is not None:
            results = [r for r in results if r.response_quality == response_quality]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        query_category: QueryCategory = QueryCategory.INVESTIGATION,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AssistantAnalysis:
        analysis = AssistantAnalysis(
            name=name,
            query_category=query_category,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "soc_assistant_analytics_engine.analysis_added",
            name=name,
            query_category=query_category.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations -------------------------------------

    def track_query(self) -> list[dict[str, Any]]:
        """Track query patterns by category."""
        cat_data: dict[str, list[AssistantQueryRecord]] = {}
        for r in self._records:
            cat_data.setdefault(r.query_category.value, []).append(r)
        results: list[dict[str, Any]] = []
        for cat, records in cat_data.items():
            avg_time = round(
                sum(r.response_time_ms for r in records) / len(records),
                2,
            )
            avg_score = round(sum(r.score for r in records) / len(records), 2)
            quality_dist: dict[str, int] = {}
            for r in records:
                qv = r.response_quality.value
                quality_dist[qv] = quality_dist.get(qv, 0) + 1
            results.append(
                {
                    "category": cat,
                    "query_count": len(records),
                    "avg_response_time_ms": avg_time,
                    "avg_score": avg_score,
                    "quality_distribution": quality_dist,
                }
            )
        return sorted(
            results,
            key=lambda x: x["query_count"],
            reverse=True,
        )

    def measure_effectiveness(self) -> dict[str, Any]:
        """Measure overall assistant effectiveness."""
        if not self._records:
            return {
                "total_queries": 0,
                "effectiveness_score": 0.0,
            }
        total = len(self._records)
        quality_scores = {
            ResponseQuality.EXCELLENT: 1.0,
            ResponseQuality.GOOD: 0.75,
            ResponseQuality.ADEQUATE: 0.5,
            ResponseQuality.POOR: 0.0,
        }
        sat_scores = {
            AnalystSatisfaction.VERY_SATISFIED: 1.0,
            AnalystSatisfaction.SATISFIED: 0.75,
            AnalystSatisfaction.NEUTRAL: 0.5,
            AnalystSatisfaction.DISSATISFIED: 0.0,
        }
        avg_quality = round(
            sum(quality_scores.get(r.response_quality, 0.5) for r in self._records) / total,
            3,
        )
        avg_satisfaction = round(
            sum(sat_scores.get(r.analyst_satisfaction, 0.5) for r in self._records) / total,
            3,
        )
        avg_time = round(sum(r.response_time_ms for r in self._records) / total, 2)
        effectiveness = round((avg_quality + avg_satisfaction) / 2, 3)
        return {
            "total_queries": total,
            "avg_quality_score": avg_quality,
            "avg_satisfaction_score": avg_satisfaction,
            "avg_response_time_ms": avg_time,
            "effectiveness_score": effectiveness,
            "rating": (
                "excellent"
                if effectiveness >= 0.85
                else (
                    "good"
                    if effectiveness >= 0.7
                    else ("needs_improvement" if effectiveness >= 0.5 else "poor")
                )
            ),
        }

    def identify_knowledge_gaps(self) -> list[dict[str, Any]]:
        """Identify categories with poor responses."""
        cat_data: dict[str, list[AssistantQueryRecord]] = {}
        for r in self._records:
            cat_data.setdefault(r.query_category.value, []).append(r)
        gaps: list[dict[str, Any]] = []
        for cat, records in cat_data.items():
            poor_count = sum(1 for r in records if r.response_quality == ResponseQuality.POOR)
            dissatisfied = sum(
                1 for r in records if r.analyst_satisfaction == AnalystSatisfaction.DISSATISFIED
            )
            total = len(records)
            poor_rate = round(poor_count / total * 100, 2)
            if poor_rate > 10 or dissatisfied > 0:
                gaps.append(
                    {
                        "category": cat,
                        "total_queries": total,
                        "poor_responses": poor_count,
                        "poor_rate_pct": poor_rate,
                        "dissatisfied_count": dissatisfied,
                        "recommendation": ("Retrain on " + cat + " queries"),
                    }
                )
        return sorted(
            gaps,
            key=lambda x: x["poor_rate_pct"],
            reverse=True,
        )

    # -- standard methods --------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.query_category.value
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
                        "query_category": r.query_category.value,
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

    # -- report / stats ----------------------------------------

    def generate_report(self) -> AssistantReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.query_category.value] = by_e1.get(r.query_category.value, 0) + 1
            by_e2[r.response_quality.value] = by_e2.get(r.response_quality.value, 0) + 1
            by_e3[r.analyst_satisfaction.value] = by_e3.get(r.analyst_satisfaction.value, 0) + 1
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
            recs.append("SOC Assistant Analytics Engine is healthy")
        return AssistantReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_query_category=by_e1,
            by_response_quality=by_e2,
            by_analyst_satisfaction=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("soc_assistant_analytics_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.query_category.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "query_category_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
