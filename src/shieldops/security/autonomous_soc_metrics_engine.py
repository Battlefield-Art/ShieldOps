"""Autonomous SOC Metrics Engine — track autonomous SOC performance."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SOCMetric(StrEnum):
    MTTD = "mttd"
    MTTR = "mttr"
    AUTOMATION_RATE = "automation_rate"
    FP_RATE = "fp_rate"
    ANALYST_LOAD = "analyst_load"


class PerformanceTrend(StrEnum):
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"


class AutomationTier(StrEnum):
    FULL = "full"
    SUPERVISED = "supervised"
    MANUAL = "manual"


# --- Models ---


class AutonomousSOCRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    soc_metric: SOCMetric = SOCMetric.MTTD
    performance_trend: PerformanceTrend = PerformanceTrend.STABLE
    automation_tier: AutomationTier = AutomationTier.MANUAL
    score: float = 0.0
    value: float = 0.0
    alert_count: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AutonomousSOCAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    soc_metric: SOCMetric = SOCMetric.MTTD
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AutonomousSOCReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_soc_metric: dict[str, int] = Field(default_factory=dict)
    by_performance_trend: dict[str, int] = Field(default_factory=dict)
    by_automation_tier: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AutonomousSOCMetricsEngine:
    """Track autonomous SOC performance metrics."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AutonomousSOCRecord] = []
        self._analyses: list[AutonomousSOCAnalysis] = []
        logger.info(
            "autonomous_soc_metrics.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ---

    def add_record(
        self,
        name: str,
        soc_metric: SOCMetric = SOCMetric.MTTD,
        performance_trend: PerformanceTrend = (PerformanceTrend.STABLE),
        automation_tier: AutomationTier = (AutomationTier.MANUAL),
        score: float = 0.0,
        value: float = 0.0,
        alert_count: int = 0,
        service: str = "",
        team: str = "",
    ) -> AutonomousSOCRecord:
        record = AutonomousSOCRecord(
            name=name,
            soc_metric=soc_metric,
            performance_trend=performance_trend,
            automation_tier=automation_tier,
            score=score,
            value=value,
            alert_count=alert_count,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "autonomous_soc_metrics.record_added",
            record_id=record.id,
            name=name,
            soc_metric=soc_metric.value,
        )
        return record

    def get_record(self, record_id: str) -> AutonomousSOCRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        soc_metric: SOCMetric | None = None,
        automation_tier: (AutomationTier | None) = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AutonomousSOCRecord]:
        results = list(self._records)
        if soc_metric is not None:
            results = [r for r in results if r.soc_metric == soc_metric]
        if automation_tier is not None:
            results = [r for r in results if r.automation_tier == automation_tier]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        soc_metric: SOCMetric = SOCMetric.MTTD,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AutonomousSOCAnalysis:
        analysis = AutonomousSOCAnalysis(
            name=name,
            soc_metric=soc_metric,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "autonomous_soc_metrics.analysis_added",
            name=name,
            soc_metric=soc_metric.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ---

    def track_metric(
        self,
    ) -> list[dict[str, Any]]:
        """Track SOC metrics over time by metric type."""
        metric_data: dict[str, list[AutonomousSOCRecord]] = {}
        for r in self._records:
            metric_data.setdefault(r.soc_metric.value, []).append(r)
        results: list[dict[str, Any]] = []
        for metric, records in metric_data.items():
            values = [r.value for r in records]
            avg_val = round(sum(values) / len(values), 2)
            trend_ct: dict[str, int] = {}
            for r in records:
                t = r.performance_trend.value
                trend_ct[t] = trend_ct.get(t, 0) + 1
            dominant = max(
                trend_ct,
                key=trend_ct.get,  # type: ignore[arg-type]
            )
            results.append(
                {
                    "metric": metric,
                    "sample_count": len(records),
                    "avg_value": avg_val,
                    "min_value": round(min(values), 2),
                    "max_value": round(max(values), 2),
                    "dominant_trend": dominant,
                }
            )
        return results

    def calculate_automation_rate(
        self,
    ) -> dict[str, Any]:
        """Calculate overall automation rate."""
        if not self._records:
            return {
                "automation_rate": 0.0,
                "total": 0,
            }
        tier_ct: dict[str, int] = {}
        for r in self._records:
            t = r.automation_tier.value
            tier_ct[t] = tier_ct.get(t, 0) + 1
        total = len(self._records)
        full = tier_ct.get("full", 0)
        supervised = tier_ct.get("supervised", 0)
        auto_rate = round(
            (full + supervised * 0.5) / total * 100,
            1,
        )
        return {
            "automation_rate": auto_rate,
            "total": total,
            "tier_distribution": tier_ct,
            "full_auto_pct": round(full / total * 100, 1),
        }

    def forecast_capacity(
        self,
    ) -> list[dict[str, Any]]:
        """Forecast SOC capacity needs."""
        team_data: dict[str, list[AutonomousSOCRecord]] = {}
        for r in self._records:
            if r.team:
                team_data.setdefault(r.team, []).append(r)
        forecasts: list[dict[str, Any]] = []
        for t, records in team_data.items():
            alerts = sum(r.alert_count for r in records)
            auto_ct = sum(1 for r in records if r.automation_tier == AutomationTier.FULL)
            total = len(records)
            auto_pct = round(auto_ct / total * 100, 1) if total else 0.0
            degrading = sum(1 for r in records if r.performance_trend == PerformanceTrend.DEGRADING)
            forecasts.append(
                {
                    "team": t,
                    "total_alerts": alerts,
                    "automation_pct": auto_pct,
                    "degrading_metrics": degrading,
                    "needs_scaling": (degrading > total * 0.3),
                    "recommendation": (
                        "Scale team capacity" if degrading > total * 0.3 else "Capacity adequate"
                    ),
                }
            )
        return sorted(
            forecasts,
            key=lambda x: x["degrading_metrics"],
            reverse=True,
        )

    # -- standard methods ---

    def analyze_distribution(
        self,
    ) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.soc_metric.value
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
                        "soc_metric": (r.soc_metric.value),
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
    ) -> AutonomousSOCReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            k1 = r.soc_metric.value
            by_e1[k1] = by_e1.get(k1, 0) + 1
            k2 = r.performance_trend.value
            by_e2[k2] = by_e2.get(k2, 0) + 1
            k3 = r.automation_tier.value
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
            recs.append("Autonomous SOC Metrics healthy")
        return AutonomousSOCReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_soc_metric=by_e1,
            by_performance_trend=by_e2,
            by_automation_tier=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("autonomous_soc_metrics.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.soc_metric.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "soc_metric_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
