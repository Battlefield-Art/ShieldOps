"""CrossSignalCorrelationEngine — Correlate traces, metrics, and logs for root cause analysis."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SignalType(StrEnum):
    TRACE = "trace"
    METRIC = "metric"
    LOG = "log"


class CorrelationStrength(StrEnum):
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    NONE = "none"


class RootCauseConfidence(StrEnum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    UNLIKELY = "unlikely"


# --- Models ---


class CrossSignalCorrelationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    signal_type: SignalType = SignalType.TRACE
    correlation_strength: CorrelationStrength = CorrelationStrength.MODERATE
    root_cause_confidence: RootCauseConfidence = RootCauseConfidence.POSSIBLE
    score: float = 0.0
    signal_count: int = 0
    correlation_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CrossSignalCorrelationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    signal_type: SignalType = SignalType.TRACE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CrossSignalCorrelationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_signal_type: dict[str, int] = Field(default_factory=dict)
    by_correlation_strength: dict[str, int] = Field(default_factory=dict)
    by_root_cause_confidence: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CrossSignalCorrelationEngine:
    """Correlate traces + metrics + logs for unified root cause analysis."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[CrossSignalCorrelationRecord] = []
        self._analyses: list[CrossSignalCorrelationAnalysis] = []
        logger.info(
            "cross_signal_correlation_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        signal_type: SignalType = SignalType.TRACE,
        correlation_strength: CorrelationStrength = CorrelationStrength.MODERATE,
        root_cause_confidence: RootCauseConfidence = RootCauseConfidence.POSSIBLE,
        score: float = 0.0,
        signal_count: int = 0,
        correlation_id: str = "",
        service: str = "",
        team: str = "",
    ) -> CrossSignalCorrelationRecord:
        record = CrossSignalCorrelationRecord(
            name=name,
            signal_type=signal_type,
            correlation_strength=correlation_strength,
            root_cause_confidence=root_cause_confidence,
            score=score,
            signal_count=signal_count,
            correlation_id=correlation_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "cross_signal_correlation_engine.record_added",
            record_id=record.id,
            name=name,
            signal_type=signal_type.value,
            correlation_strength=correlation_strength.value,
        )
        return record

    def get_record(self, record_id: str) -> CrossSignalCorrelationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        signal_type: SignalType | None = None,
        correlation_strength: CorrelationStrength | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CrossSignalCorrelationRecord]:
        results = list(self._records)
        if signal_type is not None:
            results = [r for r in results if r.signal_type == signal_type]
        if correlation_strength is not None:
            results = [r for r in results if r.correlation_strength == correlation_strength]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        signal_type: SignalType = SignalType.TRACE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CrossSignalCorrelationAnalysis:
        analysis = CrossSignalCorrelationAnalysis(
            name=name,
            signal_type=signal_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "cross_signal_correlation_engine.analysis_added",
            name=name,
            signal_type=signal_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def correlate_signals(self) -> list[dict[str, Any]]:
        """Correlate signals across traces, metrics, and logs by service."""
        svc_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, {})
            sig = r.signal_type.value
            svc_data[r.service][sig] = svc_data[r.service].get(sig, 0) + 1
        results: list[dict[str, Any]] = []
        all_signals = {s.value for s in SignalType}
        for svc, signals in svc_data.items():
            covered = set(signals.keys())
            missing = all_signals - covered
            coverage_pct = round(len(covered) / len(all_signals) * 100, 1)
            results.append(
                {
                    "service": svc,
                    "signal_coverage": sorted(covered),
                    "missing_signals": sorted(missing),
                    "coverage_pct": coverage_pct,
                    "total_signals": sum(signals.values()),
                }
            )
        return sorted(results, key=lambda x: x["coverage_pct"])

    def identify_causal_chains(self) -> list[dict[str, Any]]:
        """Identify causal chains across correlated signals."""
        chains: list[dict[str, Any]] = []
        corr_groups: dict[str, list[CrossSignalCorrelationRecord]] = {}
        for r in self._records:
            if r.correlation_id:
                corr_groups.setdefault(r.correlation_id, []).append(r)
        for corr_id, records in corr_groups.items():
            signal_types = sorted({r.signal_type.value for r in records})
            if len(signal_types) > 1:
                chains.append(
                    {
                        "correlation_id": corr_id,
                        "signal_types": signal_types,
                        "chain_length": len(records),
                        "services": sorted({r.service for r in records}),
                        "avg_score": round(sum(r.score for r in records) / len(records), 2),
                        "strongest_correlation": max(r.correlation_strength.value for r in records),
                    }
                )
        return sorted(chains, key=lambda x: x["chain_length"], reverse=True)

    def compute_root_cause_confidence(self) -> list[dict[str, Any]]:
        """Compute root cause confidence per service based on signal correlation."""
        svc_data: dict[str, list[CrossSignalCorrelationRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        confidence_weights = {
            RootCauseConfidence.CONFIRMED: 1.0,
            RootCauseConfidence.PROBABLE: 0.75,
            RootCauseConfidence.POSSIBLE: 0.5,
            RootCauseConfidence.UNLIKELY: 0.25,
        }
        results: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            weighted_sum = sum(
                confidence_weights.get(r.root_cause_confidence, 0.0) for r in records
            )
            avg_confidence = round(weighted_sum / len(records), 2) if records else 0.0
            results.append(
                {
                    "service": svc,
                    "total_signals": len(records),
                    "avg_confidence": avg_confidence,
                    "confirmed_count": sum(
                        1
                        for r in records
                        if r.root_cause_confidence == RootCauseConfidence.CONFIRMED
                    ),
                    "probable_count": sum(
                        1
                        for r in records
                        if r.root_cause_confidence == RootCauseConfidence.PROBABLE
                    ),
                }
            )
        return sorted(results, key=lambda x: x["avg_confidence"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.signal_type.value
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
                        "signal_type": r.signal_type.value,
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

    def generate_report(self) -> CrossSignalCorrelationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.signal_type.value] = by_e1.get(r.signal_type.value, 0) + 1
            by_e2[r.correlation_strength.value] = by_e2.get(r.correlation_strength.value, 0) + 1
            by_e3[r.root_cause_confidence.value] = by_e3.get(r.root_cause_confidence.value, 0) + 1
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
            recs.append("Cross Signal Correlation Engine is healthy")
        return CrossSignalCorrelationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_signal_type=by_e1,
            by_correlation_strength=by_e2,
            by_root_cause_confidence=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("cross_signal_correlation_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.signal_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "signal_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
