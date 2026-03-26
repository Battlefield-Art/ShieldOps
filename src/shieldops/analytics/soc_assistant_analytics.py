"""SOC Assistant Analytics — AI query effectiveness."""

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
    THREAT_INVESTIGATION = "threat_investigation"
    ALERT_TRIAGE = "alert_triage"
    INCIDENT_RESPONSE = "incident_response"
    POLICY_LOOKUP = "policy_lookup"
    FORENSIC_ANALYSIS = "forensic_analysis"


class ResponseQuality(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    ADEQUATE = "adequate"
    POOR = "poor"
    INCORRECT = "incorrect"


class AnalystSatisfaction(StrEnum):
    VERY_SATISFIED = "very_satisfied"
    SATISFIED = "satisfied"
    NEUTRAL = "neutral"
    DISSATISFIED = "dissatisfied"
    VERY_DISSATISFIED = "very_dissatisfied"


# --- Models ---


class SOCAssistantRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query_id: str = ""
    category: QueryCategory = QueryCategory.ALERT_TRIAGE
    quality: ResponseQuality = ResponseQuality.GOOD
    satisfaction: AnalystSatisfaction = AnalystSatisfaction.NEUTRAL
    analyst_id: str = ""
    query_text: str = ""
    response_time_ms: float = 0.0
    tokens_used: int = 0
    was_helpful: bool = True
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class SOCAssistantAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query_id: str = ""
    category: QueryCategory = QueryCategory.ALERT_TRIAGE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SOCAssistantReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_response_time_ms: float = 0.0
    helpful_rate_pct: float = 0.0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_quality: dict[str, int] = Field(default_factory=dict)
    by_satisfaction: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class SOCAssistantAnalytics:
    """Track AI assistant query effectiveness."""

    def __init__(
        self,
        max_records: int = 200000,
        quality_threshold: float = 0.7,
    ) -> None:
        self._max_records = max_records
        self._threshold = quality_threshold
        self._records: list[SOCAssistantRecord] = []
        self._analyses: list[SOCAssistantAnalysis] = []
        logger.info(
            "soc_assistant_analytics.initialized",
            max_records=max_records,
            quality_threshold=quality_threshold,
        )

    # -- record / get / list -----------------------------------

    def add_record(
        self,
        query_id: str,
        category: QueryCategory = (QueryCategory.ALERT_TRIAGE),
        quality: ResponseQuality = (ResponseQuality.GOOD),
        satisfaction: AnalystSatisfaction = (AnalystSatisfaction.NEUTRAL),
        analyst_id: str = "",
        query_text: str = "",
        response_time_ms: float = 0.0,
        tokens_used: int = 0,
        was_helpful: bool = True,
        service: str = "",
        team: str = "",
    ) -> SOCAssistantRecord:
        record = SOCAssistantRecord(
            query_id=query_id,
            category=category,
            quality=quality,
            satisfaction=satisfaction,
            analyst_id=analyst_id,
            query_text=query_text,
            response_time_ms=response_time_ms,
            tokens_used=tokens_used,
            was_helpful=was_helpful,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "soc_assistant_analytics.record_added",
            record_id=record.id,
            query_id=query_id,
            category=category.value,
            quality=quality.value,
        )
        return record

    def get_record(self, record_id: str) -> SOCAssistantRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        category: QueryCategory | None = None,
        quality: ResponseQuality | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[SOCAssistantRecord]:
        results = list(self._records)
        if category is not None:
            results = [r for r in results if r.category == category]
        if quality is not None:
            results = [r for r in results if r.quality == quality]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def process(self, query_id: str) -> SOCAssistantAnalysis:
        matched = [r for r in self._records if r.query_id == query_id]
        quality_scores = {
            ResponseQuality.EXCELLENT: 1.0,
            ResponseQuality.GOOD: 0.8,
            ResponseQuality.ADEQUATE: 0.5,
            ResponseQuality.POOR: 0.2,
            ResponseQuality.INCORRECT: 0.0,
        }
        scores = [quality_scores.get(r.quality, 0.5) for r in matched]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        breached = avg < self._threshold
        analysis = SOCAssistantAnalysis(
            query_id=query_id,
            category=(matched[-1].category if matched else QueryCategory.ALERT_TRIAGE),
            analysis_score=avg,
            threshold=self._threshold,
            breached=breached,
            description=(f"Quality {avg} for {query_id}"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ------------------------------------

    def track_query(
        self,
        query_id: str,
        analyst_id: str,
        category: QueryCategory,
        query_text: str = "",
        response_time_ms: float = 0.0,
        quality: ResponseQuality = (ResponseQuality.GOOD),
    ) -> dict[str, Any]:
        """Track an analyst query."""
        record = self.add_record(
            query_id=query_id,
            analyst_id=analyst_id,
            category=category,
            query_text=query_text,
            response_time_ms=response_time_ms,
            quality=quality,
        )
        return {
            "record_id": record.id,
            "query_id": query_id,
            "analyst_id": analyst_id,
            "category": category.value,
            "quality": quality.value,
            "response_time_ms": response_time_ms,
        }

    def measure_effectiveness(
        self,
    ) -> dict[str, Any]:
        """Measure AI assistant effectiveness."""
        if not self._records:
            return {
                "total_queries": 0,
                "effectiveness_score": 0.0,
            }
        quality_scores = {
            ResponseQuality.EXCELLENT: 1.0,
            ResponseQuality.GOOD: 0.8,
            ResponseQuality.ADEQUATE: 0.5,
            ResponseQuality.POOR: 0.2,
            ResponseQuality.INCORRECT: 0.0,
        }
        scores = [quality_scores.get(r.quality, 0.5) for r in self._records]
        avg_quality = round(sum(scores) / len(scores), 4)
        helpful_ct = sum(1 for r in self._records if r.was_helpful)
        helpful_rate = round(
            helpful_ct / len(self._records) * 100,
            2,
        )
        times = [r.response_time_ms for r in self._records]
        avg_time = round(sum(times) / len(times), 2)
        by_cat: dict[str, float] = {}
        cat_counts: dict[str, int] = {}
        for r in self._records:
            key = r.category.value
            s = quality_scores.get(r.quality, 0.5)
            by_cat[key] = by_cat.get(key, 0.0) + s
            cat_counts[key] = cat_counts.get(key, 0) + 1
        cat_avg = {k: round(by_cat[k] / cat_counts[k], 4) for k in by_cat}
        return {
            "total_queries": len(self._records),
            "effectiveness_score": avg_quality,
            "helpful_rate_pct": helpful_rate,
            "avg_response_time_ms": avg_time,
            "by_category": cat_avg,
        }

    def identify_knowledge_gaps(
        self,
    ) -> list[dict[str, Any]]:
        """Identify areas with low quality."""
        cat_data: dict[str, dict[str, Any]] = {}
        quality_scores = {
            ResponseQuality.EXCELLENT: 1.0,
            ResponseQuality.GOOD: 0.8,
            ResponseQuality.ADEQUATE: 0.5,
            ResponseQuality.POOR: 0.2,
            ResponseQuality.INCORRECT: 0.0,
        }
        for r in self._records:
            key = r.category.value
            if key not in cat_data:
                cat_data[key] = {
                    "total": 0,
                    "score_sum": 0.0,
                    "poor_count": 0,
                }
            cat_data[key]["total"] += 1
            cat_data[key]["score_sum"] += quality_scores.get(r.quality, 0.5)
            if r.quality in (
                ResponseQuality.POOR,
                ResponseQuality.INCORRECT,
            ):
                cat_data[key]["poor_count"] += 1
        gaps: list[dict[str, Any]] = []
        for cat, data in cat_data.items():
            avg = round(
                data["score_sum"] / data["total"],
                4,
            )
            if avg < self._threshold:
                gaps.append(
                    {
                        "category": cat,
                        "avg_quality": avg,
                        "total_queries": data["total"],
                        "poor_count": (data["poor_count"]),
                        "gap_severity": round(self._threshold - avg, 4),
                    }
                )
        gaps.sort(
            key=lambda x: x["gap_severity"],
            reverse=True,
        )
        return gaps

    # -- report / stats ----------------------------------------

    def generate_report(
        self,
    ) -> SOCAssistantReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.category.value] = by_e1.get(r.category.value, 0) + 1
            by_e2[r.quality.value] = by_e2.get(r.quality.value, 0) + 1
            by_e3[r.satisfaction.value] = by_e3.get(r.satisfaction.value, 0) + 1
        times = [r.response_time_ms for r in self._records]
        avg_time = round(sum(times) / len(times), 2) if times else 0.0
        helpful_ct = sum(1 for r in self._records if r.was_helpful)
        total = len(self._records)
        helpful_rate = round(helpful_ct / total * 100, 2) if total else 0.0
        poor_ct = sum(
            1
            for r in self._records
            if r.quality
            in (
                ResponseQuality.POOR,
                ResponseQuality.INCORRECT,
            )
        )
        top_gaps = [
            r.query_id
            for r in self._records
            if r.quality
            in (
                ResponseQuality.POOR,
                ResponseQuality.INCORRECT,
            )
        ][:5]
        recs: list[str] = []
        if poor_ct > 0:
            recs.append(f"{poor_ct} poor/incorrect response(s)")
        if helpful_rate < 80:
            recs.append("Helpful rate below 80% target")
        if not recs:
            recs.append("SOC Assistant Analytics healthy")
        return SOCAssistantReport(
            total_records=total,
            total_analyses=len(self._analyses),
            gap_count=poor_ct,
            avg_response_time_ms=avg_time,
            helpful_rate_pct=helpful_rate,
            by_category=by_e1,
            by_quality=by_e2,
            by_satisfaction=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("soc_assistant_analytics.cleared")
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
            "category_distribution": e1_dist,
            "unique_analysts": len({r.analyst_id for r in self._records}),
            "helpful_count": sum(1 for r in self._records if r.was_helpful),
        }
