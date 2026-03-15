"""UnifiedTelemetryCostEngine — Track unified telemetry costs across signals."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TelemetrySignal(StrEnum):
    TRACES = "traces"
    METRICS = "metrics"
    LOGS = "logs"


class CostDriver(StrEnum):
    VOLUME = "volume"
    CARDINALITY = "cardinality"
    RETENTION = "retention"
    EGRESS = "egress"


class CostTrend(StrEnum):
    INCREASING = "increasing"
    STABLE = "stable"
    DECREASING = "decreasing"


# --- Models ---


class UnifiedTelemetryCostRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    signal: TelemetrySignal = TelemetrySignal.TRACES
    driver: CostDriver = CostDriver.VOLUME
    trend: CostTrend = CostTrend.STABLE
    score: float = 0.0
    cost_usd: float = 0.0
    volume_gb: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class UnifiedTelemetryCostAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    signal: TelemetrySignal = TelemetrySignal.TRACES
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class UnifiedTelemetryCostReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_signal: dict[str, int] = Field(default_factory=dict)
    by_driver: dict[str, int] = Field(default_factory=dict)
    by_trend: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class UnifiedTelemetryCostEngine:
    """Track unified telemetry costs across all three signals."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[UnifiedTelemetryCostRecord] = []
        self._analyses: list[UnifiedTelemetryCostAnalysis] = []
        logger.info(
            "unified_telemetry_cost_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        signal: TelemetrySignal = TelemetrySignal.TRACES,
        driver: CostDriver = CostDriver.VOLUME,
        trend: CostTrend = CostTrend.STABLE,
        score: float = 0.0,
        cost_usd: float = 0.0,
        volume_gb: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> UnifiedTelemetryCostRecord:
        record = UnifiedTelemetryCostRecord(
            name=name,
            signal=signal,
            driver=driver,
            trend=trend,
            score=score,
            cost_usd=cost_usd,
            volume_gb=volume_gb,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "unified_telemetry_cost_engine.record_added",
            record_id=record.id,
            name=name,
            signal=signal.value,
            driver=driver.value,
        )
        return record

    def get_record(self, record_id: str) -> UnifiedTelemetryCostRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        signal: TelemetrySignal | None = None,
        driver: CostDriver | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[UnifiedTelemetryCostRecord]:
        results = list(self._records)
        if signal is not None:
            results = [r for r in results if r.signal == signal]
        if driver is not None:
            results = [r for r in results if r.driver == driver]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        signal: TelemetrySignal = TelemetrySignal.TRACES,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> UnifiedTelemetryCostAnalysis:
        analysis = UnifiedTelemetryCostAnalysis(
            name=name,
            signal=signal,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "unified_telemetry_cost_engine.analysis_added",
            name=name,
            signal=signal.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_cost_by_signal(self) -> list[dict[str, Any]]:
        """Compute total and average cost per telemetry signal."""
        signal_data: dict[str, list[float]] = {}
        for r in self._records:
            signal_data.setdefault(r.signal.value, []).append(r.cost_usd)
        results: list[dict[str, Any]] = []
        total_cost = sum(r.cost_usd for r in self._records)
        for sig, costs in signal_data.items():
            sig_total = round(sum(costs), 2)
            results.append(
                {
                    "signal": sig,
                    "total_cost_usd": sig_total,
                    "avg_cost_usd": round(sig_total / len(costs), 2),
                    "record_count": len(costs),
                    "pct_of_total": round(sig_total / total_cost * 100, 1)
                    if total_cost > 0
                    else 0.0,
                }
            )
        return sorted(results, key=lambda x: x["total_cost_usd"], reverse=True)

    def identify_cost_drivers(self) -> list[dict[str, Any]]:
        """Identify top cost drivers across all signals."""
        driver_data: dict[str, dict[str, float]] = {}
        for r in self._records:
            key = f"{r.service}:{r.driver.value}"
            if key not in driver_data:
                driver_data[key] = {
                    "total_cost": 0.0,
                    "total_volume": 0.0,
                    "count": 0,
                }
            driver_data[key]["total_cost"] += r.cost_usd
            driver_data[key]["total_volume"] += r.volume_gb
            driver_data[key]["count"] += 1
        results: list[dict[str, Any]] = []
        for key, data in driver_data.items():
            svc, driver = key.split(":", 1)
            results.append(
                {
                    "service": svc,
                    "driver": driver,
                    "total_cost_usd": round(data["total_cost"], 2),
                    "total_volume_gb": round(data["total_volume"], 2),
                    "record_count": int(data["count"]),
                    "priority": "high"
                    if data["total_cost"] > 1000
                    else "medium"
                    if data["total_cost"] > 100
                    else "low",
                }
            )
        return sorted(results, key=lambda x: x["total_cost_usd"], reverse=True)

    def recommend_cost_optimizations(self) -> list[dict[str, Any]]:
        """Recommend cost optimizations based on trends and drivers."""
        recommendations: list[dict[str, Any]] = []
        increasing = [r for r in self._records if r.trend == CostTrend.INCREASING]
        svc_increasing: dict[str, list[UnifiedTelemetryCostRecord]] = {}
        for r in increasing:
            svc_increasing.setdefault(r.service, []).append(r)
        for svc, records in svc_increasing.items():
            total = round(sum(r.cost_usd for r in records), 2)
            recommendations.append(
                {
                    "service": svc,
                    "issue": "increasing_cost_trend",
                    "total_cost_usd": total,
                    "record_count": len(records),
                    "priority": "high",
                    "suggestion": f"Investigate rising costs for {svc} (${total})",
                }
            )
        high_vol = [r for r in self._records if r.driver == CostDriver.VOLUME and r.volume_gb > 100]
        for r in high_vol:
            recommendations.append(
                {
                    "service": r.service,
                    "issue": "high_volume",
                    "volume_gb": r.volume_gb,
                    "cost_usd": r.cost_usd,
                    "priority": "medium",
                    "suggestion": f"Apply sampling/filtering for {r.service} ({r.volume_gb} GB)",
                }
            )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else 1 if x["priority"] == "medium" else 2,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.signal.value
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
                        "signal": r.signal.value,
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

    def generate_report(self) -> UnifiedTelemetryCostReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.signal.value] = by_e1.get(r.signal.value, 0) + 1
            by_e2[r.driver.value] = by_e2.get(r.driver.value, 0) + 1
            by_e3[r.trend.value] = by_e3.get(r.trend.value, 0) + 1
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
            recs.append("Unified Telemetry Cost Engine is healthy")
        return UnifiedTelemetryCostReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_signal=by_e1,
            by_driver=by_e2,
            by_trend=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("unified_telemetry_cost_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.signal.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "signal_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
