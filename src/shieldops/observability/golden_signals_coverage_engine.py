"""GoldenSignalsCoverageEngine — Track coverage of four golden signals per service."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class GoldenSignal(StrEnum):
    LATENCY = "latency"
    TRAFFIC = "traffic"
    ERRORS = "errors"
    SATURATION = "saturation"


class CoverageStatus(StrEnum):
    COVERED = "covered"
    PARTIAL = "partial"
    MISSING = "missing"


class SignalQuality(StrEnum):
    EXCELLENT = "excellent"
    ADEQUATE = "adequate"
    INSUFFICIENT = "insufficient"


# --- Models ---


class GoldenSignalsCoverageRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    golden_signal: GoldenSignal = GoldenSignal.LATENCY
    coverage_status: CoverageStatus = CoverageStatus.COVERED
    signal_quality: SignalQuality = SignalQuality.EXCELLENT
    score: float = 0.0
    metric_count: int = 0
    alert_configured: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class GoldenSignalsCoverageAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    golden_signal: GoldenSignal = GoldenSignal.LATENCY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class GoldenSignalsCoverageReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_golden_signal: dict[str, int] = Field(default_factory=dict)
    by_coverage_status: dict[str, int] = Field(default_factory=dict)
    by_signal_quality: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class GoldenSignalsCoverageEngine:
    """Track coverage of the four golden signals (latency, traffic, errors, saturation)."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[GoldenSignalsCoverageRecord] = []
        self._analyses: list[GoldenSignalsCoverageAnalysis] = []
        logger.info(
            "golden_signals_coverage_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        golden_signal: GoldenSignal = GoldenSignal.LATENCY,
        coverage_status: CoverageStatus = CoverageStatus.COVERED,
        signal_quality: SignalQuality = SignalQuality.EXCELLENT,
        score: float = 0.0,
        metric_count: int = 0,
        alert_configured: bool = False,
        service: str = "",
        team: str = "",
    ) -> GoldenSignalsCoverageRecord:
        record = GoldenSignalsCoverageRecord(
            name=name,
            golden_signal=golden_signal,
            coverage_status=coverage_status,
            signal_quality=signal_quality,
            score=score,
            metric_count=metric_count,
            alert_configured=alert_configured,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "golden_signals_coverage_engine.record_added",
            record_id=record.id,
            name=name,
            golden_signal=golden_signal.value,
            coverage_status=coverage_status.value,
        )
        return record

    def get_record(self, record_id: str) -> GoldenSignalsCoverageRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        golden_signal: GoldenSignal | None = None,
        coverage_status: CoverageStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[GoldenSignalsCoverageRecord]:
        results = list(self._records)
        if golden_signal is not None:
            results = [r for r in results if r.golden_signal == golden_signal]
        if coverage_status is not None:
            results = [r for r in results if r.coverage_status == coverage_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        golden_signal: GoldenSignal = GoldenSignal.LATENCY,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> GoldenSignalsCoverageAnalysis:
        analysis = GoldenSignalsCoverageAnalysis(
            name=name,
            golden_signal=golden_signal,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "golden_signals_coverage_engine.analysis_added",
            name=name,
            golden_signal=golden_signal.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_golden_signal_coverage(self) -> list[dict[str, Any]]:
        """Compute coverage of all four golden signals per service."""
        svc_signals: dict[str, dict[str, list[float]]] = {}
        for r in self._records:
            svc_signals.setdefault(r.service, {})
            svc_signals[r.service].setdefault(r.golden_signal.value, []).append(r.score)
        all_signals = {s.value for s in GoldenSignal}
        results: list[dict[str, Any]] = []
        for svc, signals in svc_signals.items():
            covered = set(signals.keys())
            missing = all_signals - covered
            coverage_pct = round(len(covered) / len(all_signals) * 100, 1)
            avg_scores = {
                sig: round(sum(scores) / len(scores), 2) for sig, scores in signals.items()
            }
            results.append(
                {
                    "service": svc,
                    "covered_signals": sorted(covered),
                    "missing_signals": sorted(missing),
                    "coverage_pct": coverage_pct,
                    "avg_scores": avg_scores,
                }
            )
        return sorted(results, key=lambda x: x["coverage_pct"])

    def identify_uncovered_services(self) -> list[dict[str, Any]]:
        """Identify services missing one or more golden signals."""
        svc_signals: dict[str, set[str]] = {}
        for r in self._records:
            svc_signals.setdefault(r.service, set()).add(r.golden_signal.value)
        all_signals = {s.value for s in GoldenSignal}
        gaps: list[dict[str, Any]] = []
        for svc, signals in svc_signals.items():
            missing = all_signals - signals
            if missing:
                gaps.append(
                    {
                        "service": svc,
                        "missing_signals": sorted(missing),
                        "covered_signals": sorted(signals),
                        "gap_count": len(missing),
                    }
                )
        return sorted(gaps, key=lambda x: x["gap_count"], reverse=True)

    def recommend_instrumentation(self) -> list[dict[str, Any]]:
        """Recommend instrumentation improvements for golden signal coverage."""
        recommendations: list[dict[str, Any]] = []
        missing_records = [r for r in self._records if r.coverage_status == CoverageStatus.MISSING]
        for r in missing_records:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "signal": r.golden_signal.value,
                    "issue": "missing_coverage",
                    "priority": "high",
                    "suggestion": f"Add {r.golden_signal.value} instrumentation for {r.service}",
                }
            )
        low_quality = [
            r
            for r in self._records
            if r.signal_quality == SignalQuality.INSUFFICIENT
            and r.coverage_status != CoverageStatus.MISSING
        ]
        for r in low_quality:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "signal": r.golden_signal.value,
                    "issue": "insufficient_quality",
                    "priority": "medium",
                    "suggestion": f"Improve {r.golden_signal.value} signal quality for {r.service}",
                }
            )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else 1,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.golden_signal.value
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
                        "golden_signal": r.golden_signal.value,
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

    def generate_report(self) -> GoldenSignalsCoverageReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.golden_signal.value] = by_e1.get(r.golden_signal.value, 0) + 1
            by_e2[r.coverage_status.value] = by_e2.get(r.coverage_status.value, 0) + 1
            by_e3[r.signal_quality.value] = by_e3.get(r.signal_quality.value, 0) + 1
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
            recs.append("Golden Signals Coverage Engine is healthy")
        return GoldenSignalsCoverageReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_golden_signal=by_e1,
            by_coverage_status=by_e2,
            by_signal_quality=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("golden_signals_coverage_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.golden_signal.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "golden_signal_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
