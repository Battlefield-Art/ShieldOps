"""SloAwareSamplingEngine — adjust telemetry sampling rates based on SLO burn rate."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SLOStatus(StrEnum):
    HEALTHY = "healthy"
    BURNING = "burning"
    CRITICAL = "critical"
    BREACHED = "breached"


class SamplingAdjustment(StrEnum):
    INCREASE = "increase"
    MAINTAIN = "maintain"
    DECREASE = "decrease"
    FULL_CAPTURE = "full_capture"


class BurnRateWindow(StrEnum):
    FAST_1H = "fast_1h"
    SLOW_6H = "slow_6h"
    MEDIUM_24H = "medium_24h"
    LONG_7D = "long_7d"


# --- Models ---


class SloAwareSamplingRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    slo_status: SLOStatus = SLOStatus.HEALTHY
    sampling_adjustment: SamplingAdjustment = SamplingAdjustment.MAINTAIN
    burn_rate_window: BurnRateWindow = BurnRateWindow.FAST_1H
    score: float = 0.0
    burn_rate: float = 0.0
    sampling_rate: float = 1.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class SloAwareSamplingAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    slo_status: SLOStatus = SLOStatus.HEALTHY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SloAwareSamplingReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_slo_status: dict[str, int] = Field(default_factory=dict)
    by_sampling_adjustment: dict[str, int] = Field(default_factory=dict)
    by_burn_rate_window: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class SloAwareSamplingEngine:
    """SLO-Aware Sampling Engine — sample more when SLOs are at risk, less when healthy."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[SloAwareSamplingRecord] = []
        self._analyses: list[SloAwareSamplingAnalysis] = []
        logger.info(
            "slo_aware_sampling_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        slo_status: SLOStatus = SLOStatus.HEALTHY,
        sampling_adjustment: SamplingAdjustment = SamplingAdjustment.MAINTAIN,
        burn_rate_window: BurnRateWindow = BurnRateWindow.FAST_1H,
        score: float = 0.0,
        burn_rate: float = 0.0,
        sampling_rate: float = 1.0,
        service: str = "",
        team: str = "",
    ) -> SloAwareSamplingRecord:
        record = SloAwareSamplingRecord(
            name=name,
            slo_status=slo_status,
            sampling_adjustment=sampling_adjustment,
            burn_rate_window=burn_rate_window,
            score=score,
            burn_rate=burn_rate,
            sampling_rate=sampling_rate,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "slo_aware_sampling_engine.record_added",
            record_id=record.id,
            name=name,
            slo_status=slo_status.value,
            burn_rate_window=burn_rate_window.value,
        )
        return record

    def get_record(self, record_id: str) -> SloAwareSamplingRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        slo_status: SLOStatus | None = None,
        sampling_adjustment: SamplingAdjustment | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[SloAwareSamplingRecord]:
        results = list(self._records)
        if slo_status is not None:
            results = [r for r in results if r.slo_status == slo_status]
        if sampling_adjustment is not None:
            results = [r for r in results if r.sampling_adjustment == sampling_adjustment]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        slo_status: SLOStatus = SLOStatus.HEALTHY,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> SloAwareSamplingAnalysis:
        analysis = SloAwareSamplingAnalysis(
            name=name,
            slo_status=slo_status,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "slo_aware_sampling_engine.analysis_added",
            name=name,
            slo_status=slo_status.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.slo_status.value
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
                        "slo_status": r.slo_status.value,
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

    def compute_slo_aware_rate(self, service_name: str) -> dict[str, Any]:
        """Compute recommended sampling rate based on SLO health for a service."""
        svc_records = [r for r in self._records if r.service == service_name]
        if not svc_records:
            return {
                "service": service_name,
                "recommended_rate": 0.1,
                "reason": "no_data",
                "slo_status": "unknown",
            }
        latest = svc_records[-1]
        if latest.slo_status == SLOStatus.BREACHED:
            rate = 1.0
            reason = "SLO breached — full capture"
        elif latest.slo_status == SLOStatus.CRITICAL:
            rate = 0.75
            reason = "SLO critical — high sampling"
        elif latest.slo_status == SLOStatus.BURNING:
            rate = 0.5
            reason = "SLO burning — increased sampling"
        else:
            rate = 0.1
            reason = "SLO healthy — baseline sampling"
        return {
            "service": service_name,
            "recommended_rate": rate,
            "reason": reason,
            "slo_status": latest.slo_status.value,
            "current_burn_rate": latest.burn_rate,
        }

    def detect_burn_rate_anomalies(
        self,
        burn_rate_threshold: float = 2.0,
    ) -> list[dict[str, Any]]:
        """Find services with unusual burn rates."""
        svc_rates: dict[str, list[float]] = {}
        for r in self._records:
            svc_rates.setdefault(r.service, []).append(r.burn_rate)
        anomalies: list[dict[str, Any]] = []
        for svc, rates in svc_rates.items():
            avg_rate = sum(rates) / len(rates)
            max_rate = max(rates)
            if max_rate > burn_rate_threshold:
                anomalies.append(
                    {
                        "service": svc,
                        "avg_burn_rate": round(avg_rate, 4),
                        "max_burn_rate": round(max_rate, 4),
                        "sample_count": len(rates),
                        "severity": (
                            "critical" if max_rate > burn_rate_threshold * 5 else "warning"
                        ),
                    }
                )
        return sorted(anomalies, key=lambda x: x["max_burn_rate"], reverse=True)

    def estimate_sampling_savings(self) -> dict[str, Any]:
        """Estimate cost savings from SLO-aware sampling vs full capture."""
        if not self._records:
            return {
                "total_records": 0,
                "estimated_reduction_pct": 0.0,
                "services": [],
            }
        svc_data: dict[str, list[SloAwareSamplingRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        svc_savings: list[dict[str, Any]] = []
        total_full = 0
        total_sampled = 0.0
        for svc, records in svc_data.items():
            full_cost = len(records)
            sampled_cost = sum(r.sampling_rate for r in records)
            reduction = round((1.0 - sampled_cost / full_cost) * 100, 2) if full_cost > 0 else 0.0
            svc_savings.append(
                {
                    "service": svc,
                    "full_capture_cost": full_cost,
                    "sampled_cost": round(sampled_cost, 2),
                    "reduction_pct": reduction,
                }
            )
            total_full += full_cost
            total_sampled += sampled_cost
        overall_reduction = (
            round((1.0 - total_sampled / total_full) * 100, 2) if total_full > 0 else 0.0
        )
        return {
            "total_records": len(self._records),
            "estimated_reduction_pct": overall_reduction,
            "services": sorted(svc_savings, key=lambda x: x["reduction_pct"], reverse=True),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> SloAwareSamplingReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.slo_status.value] = by_e1.get(r.slo_status.value, 0) + 1
            by_e2[r.sampling_adjustment.value] = by_e2.get(r.sampling_adjustment.value, 0) + 1
            by_e3[r.burn_rate_window.value] = by_e3.get(r.burn_rate_window.value, 0) + 1
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
            recs.append("SLO-Aware Sampling Engine is healthy")
        return SloAwareSamplingReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_slo_status=by_e1,
            by_sampling_adjustment=by_e2,
            by_burn_rate_window=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("slo_aware_sampling_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.slo_status.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "slo_status_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
