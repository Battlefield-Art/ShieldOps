"""CardinalityControlEngine — monitor and control metric cardinality."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CardinalityLevel(StrEnum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    HIGH = "high"
    EXPLOSIVE = "explosive"


class ControlAction(StrEnum):
    AGGREGATE = "aggregate"
    DROP_LABEL = "drop_label"
    RATE_LIMIT = "rate_limit"
    ALLOWLIST = "allowlist"


class MetricType(StrEnum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


# --- Models ---


class CardinalityControlRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    cardinality_level: CardinalityLevel = CardinalityLevel.NORMAL
    control_action: ControlAction = ControlAction.AGGREGATE
    metric_type: MetricType = MetricType.COUNTER
    score: float = 0.0
    label_count: int = 0
    series_count: int = 0
    growth_rate_pct: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CardinalityControlAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    cardinality_level: CardinalityLevel = CardinalityLevel.NORMAL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CardinalityControlReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_cardinality_level: dict[str, int] = Field(default_factory=dict)
    by_control_action: dict[str, int] = Field(default_factory=dict)
    by_metric_type: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CardinalityControlEngine:
    """Cardinality Control Engine — detect label explosions and enforce limits."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[CardinalityControlRecord] = []
        self._analyses: list[CardinalityControlAnalysis] = []
        logger.info(
            "cardinality_control_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        cardinality_level: CardinalityLevel = CardinalityLevel.NORMAL,
        control_action: ControlAction = ControlAction.AGGREGATE,
        metric_type: MetricType = MetricType.COUNTER,
        score: float = 0.0,
        label_count: int = 0,
        series_count: int = 0,
        growth_rate_pct: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> CardinalityControlRecord:
        record = CardinalityControlRecord(
            name=name,
            cardinality_level=cardinality_level,
            control_action=control_action,
            metric_type=metric_type,
            score=score,
            label_count=label_count,
            series_count=series_count,
            growth_rate_pct=growth_rate_pct,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "cardinality_control_engine.record_added",
            record_id=record.id,
            name=name,
            cardinality_level=cardinality_level.value,
            metric_type=metric_type.value,
        )
        return record

    def get_record(self, record_id: str) -> CardinalityControlRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        cardinality_level: CardinalityLevel | None = None,
        metric_type: MetricType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CardinalityControlRecord]:
        results = list(self._records)
        if cardinality_level is not None:
            results = [r for r in results if r.cardinality_level == cardinality_level]
        if metric_type is not None:
            results = [r for r in results if r.metric_type == metric_type]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        cardinality_level: CardinalityLevel = CardinalityLevel.NORMAL,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CardinalityControlAnalysis:
        analysis = CardinalityControlAnalysis(
            name=name,
            cardinality_level=cardinality_level,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "cardinality_control_engine.analysis_added",
            name=name,
            cardinality_level=cardinality_level.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.cardinality_level.value
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
                        "cardinality_level": r.cardinality_level.value,
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

    def detect_trends(self) -> dict[str, Any]:
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [a.analysis_score for a in self._analyses]
        mid = len(vals) // 2
        first_half = vals[:mid]
        second_half = vals[mid:]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        delta = round(avg_second - avg_first, 2)
        if abs(delta) < 5.0:
            trend = "stable"
        elif delta > 0:
            trend = "improving"
        else:
            trend = "degrading"
        return {
            "trend": trend,
            "delta": delta,
            "avg_first_half": round(avg_first, 2),
            "avg_second_half": round(avg_second, 2),
        }

    def detect_cardinality_explosions(
        self,
        growth_threshold: float = 50.0,
    ) -> list[dict[str, Any]]:
        """Find metrics with rapidly growing label combinations."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if (
                r.cardinality_level in (CardinalityLevel.HIGH, CardinalityLevel.EXPLOSIVE)
                or r.growth_rate_pct > growth_threshold
            ):
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "cardinality_level": r.cardinality_level.value,
                        "series_count": r.series_count,
                        "label_count": r.label_count,
                        "growth_rate_pct": r.growth_rate_pct,
                        "service": r.service,
                    }
                )
        return sorted(results, key=lambda x: x["growth_rate_pct"], reverse=True)

    def recommend_cardinality_controls(self) -> list[dict[str, Any]]:
        """Suggest specific controls per metric based on cardinality analysis."""
        svc_data: dict[str, list[CardinalityControlRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.name, []).append(r)
        recommendations: list[dict[str, Any]] = []
        for metric_name, records in svc_data.items():
            latest = records[-1]
            actions: list[str] = []
            if latest.cardinality_level == CardinalityLevel.EXPLOSIVE:
                actions.append("Immediately drop high-cardinality labels")
                actions.append("Apply allowlist to restrict label values")
            elif latest.cardinality_level == CardinalityLevel.HIGH:
                actions.append("Aggregate label values into buckets")
                actions.append("Rate-limit new label value creation")
            elif latest.cardinality_level == CardinalityLevel.ELEVATED:
                actions.append("Monitor growth rate for escalation")
                actions.append("Consider pre-aggregation")
            else:
                actions.append("No action needed — cardinality is normal")
            if latest.growth_rate_pct > 100:
                actions.append(f"Alert: growth rate {latest.growth_rate_pct}% exceeds safe limit")
            recommendations.append(
                {
                    "metric_name": metric_name,
                    "cardinality_level": latest.cardinality_level.value,
                    "series_count": latest.series_count,
                    "growth_rate_pct": latest.growth_rate_pct,
                    "recommended_actions": actions,
                    "service": latest.service,
                }
            )
        return sorted(
            recommendations,
            key=lambda x: x["growth_rate_pct"],
            reverse=True,
        )

    def estimate_storage_impact(self, metric_name: str) -> dict[str, Any]:
        """Project storage cost from cardinality growth for a specific metric."""
        metric_records = [r for r in self._records if r.name == metric_name]
        if not metric_records:
            return {
                "metric_name": metric_name,
                "current_series": 0,
                "projected_series_30d": 0,
                "storage_impact": "unknown",
            }
        latest = metric_records[-1]
        current_series = latest.series_count
        growth_rate = latest.growth_rate_pct / 100
        projected_30d = int(current_series * (1 + growth_rate) ** 30)
        projected_90d = int(current_series * (1 + growth_rate) ** 90)
        bytes_per_series_day = 200
        current_daily_bytes = current_series * bytes_per_series_day
        projected_daily_bytes_30d = projected_30d * bytes_per_series_day
        if projected_30d > current_series * 10:
            impact = "critical"
        elif projected_30d > current_series * 3:
            impact = "high"
        elif projected_30d > current_series * 1.5:
            impact = "moderate"
        else:
            impact = "low"
        return {
            "metric_name": metric_name,
            "current_series": current_series,
            "growth_rate_pct": latest.growth_rate_pct,
            "projected_series_30d": projected_30d,
            "projected_series_90d": projected_90d,
            "current_daily_bytes": current_daily_bytes,
            "projected_daily_bytes_30d": projected_daily_bytes_30d,
            "storage_impact": impact,
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> CardinalityControlReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.cardinality_level.value] = by_e1.get(r.cardinality_level.value, 0) + 1
            by_e2[r.control_action.value] = by_e2.get(r.control_action.value, 0) + 1
            by_e3[r.metric_type.value] = by_e3.get(r.metric_type.value, 0) + 1
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
            recs.append("Cardinality Control Engine is healthy")
        return CardinalityControlReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_cardinality_level=by_e1,
            by_control_action=by_e2,
            by_metric_type=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("cardinality_control_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.cardinality_level.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "cardinality_level_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
