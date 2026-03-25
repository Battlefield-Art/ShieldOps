"""Cost Spike Detector Engine — detect and track cloud cost anomalies."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SpikeType(StrEnum):
    SUDDEN_INCREASE = "sudden_increase"
    GRADUAL_DRIFT = "gradual_drift"
    BILLING_ERROR = "billing_error"
    RESOURCE_LEAK = "resource_leak"
    LLM_OVERRUN = "llm_overrun"


class SpikeSource(StrEnum):
    COMPUTE = "compute"
    STORAGE = "storage"
    NETWORK = "network"
    DATABASE = "database"
    LLM_API = "llm_api"


class MitigationStatus(StrEnum):
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    RESOLVED = "resolved"


# --- Models ---


class CostSpikeRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    spike_id: str = ""
    spike_type: SpikeType = SpikeType.SUDDEN_INCREASE
    spike_source: SpikeSource = SpikeSource.COMPUTE
    mitigation_status: MitigationStatus = MitigationStatus.DETECTED
    expected_daily: float = 0.0
    actual_daily: float = 0.0
    deviation_pct: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CostSpikeAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    spike_type: SpikeType = SpikeType.SUDDEN_INCREASE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CostSpikeReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_spike_type: dict[str, int] = Field(default_factory=dict)
    by_spike_source: dict[str, int] = Field(default_factory=dict)
    by_mitigation_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CostSpikeDetectorEngine:
    """Cost Spike Detector Engine — detect and track cloud cost anomalies."""

    def __init__(
        self,
        max_records: int = 200000,
        deviation_threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = deviation_threshold
        self._records: list[CostSpikeRecord] = []
        self._analyses: list[CostSpikeAnalysis] = []
        logger.info(
            "cost_spike_detector_engine.initialized",
            max_records=max_records,
            deviation_threshold=deviation_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        spike_id: str,
        spike_type: SpikeType = SpikeType.SUDDEN_INCREASE,
        spike_source: SpikeSource = SpikeSource.COMPUTE,
        mitigation_status: MitigationStatus = MitigationStatus.DETECTED,
        expected_daily: float = 0.0,
        actual_daily: float = 0.0,
        deviation_pct: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> CostSpikeRecord:
        record = CostSpikeRecord(
            spike_id=spike_id,
            spike_type=spike_type,
            spike_source=spike_source,
            mitigation_status=mitigation_status,
            expected_daily=expected_daily,
            actual_daily=actual_daily,
            deviation_pct=deviation_pct,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "cost_spike_detector_engine.record_added",
            record_id=record.id,
            spike_id=spike_id,
            spike_type=spike_type.value,
            spike_source=spike_source.value,
        )
        return record

    def get_record(self, record_id: str) -> CostSpikeRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        spike_type: SpikeType | None = None,
        spike_source: SpikeSource | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CostSpikeRecord]:
        results = list(self._records)
        if spike_type is not None:
            results = [r for r in results if r.spike_type == spike_type]
        if spike_source is not None:
            results = [r for r in results if r.spike_source == spike_source]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        spike_type: SpikeType = SpikeType.SUDDEN_INCREASE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CostSpikeAnalysis:
        analysis = CostSpikeAnalysis(
            name=name,
            spike_type=spike_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "cost_spike_detector_engine.analysis_added",
            name=name,
            spike_type=spike_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_spike_sources(self) -> dict[str, Any]:
        source_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.spike_source.value
            source_data.setdefault(key, []).append(r.deviation_pct)
        result: dict[str, Any] = {}
        for k, devs in source_data.items():
            result[k] = {
                "count": len(devs),
                "avg_deviation_pct": round(sum(devs) / len(devs), 2),
            }
        return result

    def identify_unresolved_spikes(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if (
                r.mitigation_status in (MitigationStatus.DETECTED, MitigationStatus.INVESTIGATING)
                and r.deviation_pct >= self._threshold
            ):
                results.append(
                    {
                        "record_id": r.id,
                        "spike_id": r.spike_id,
                        "spike_type": r.spike_type.value,
                        "spike_source": r.spike_source.value,
                        "mitigation_status": r.mitigation_status.value,
                        "deviation_pct": r.deviation_pct,
                        "actual_daily": r.actual_daily,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["deviation_pct"], reverse=True)

    def detect_cost_trends(self) -> dict[str, Any]:
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
            trend = "increasing"
        else:
            trend = "decreasing"
        return {
            "trend": trend,
            "delta": delta,
            "avg_first_half": round(avg_first, 2),
            "avg_second_half": round(avg_second, 2),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> CostSpikeReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.spike_type.value] = by_e1.get(r.spike_type.value, 0) + 1
            by_e2[r.spike_source.value] = by_e2.get(r.spike_source.value, 0) + 1
            by_e3[r.mitigation_status.value] = by_e3.get(r.mitigation_status.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.deviation_pct >= self._threshold)
        devs = [r.deviation_pct for r in self._records]
        avg_score = round(sum(devs) / len(devs), 2) if devs else 0.0
        gap_list = self.identify_unresolved_spikes()
        top_gaps = [g["spike_id"] for g in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} spike(s) above deviation threshold ({self._threshold}%)")
        unresolved = len(gap_list)
        if unresolved > 0:
            recs.append(f"{unresolved} unresolved spike(s) require attention")
        if not recs:
            recs.append("Cost Spike Detector Engine is healthy")
        return CostSpikeReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_spike_type=by_e1,
            by_spike_source=by_e2,
            by_mitigation_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("cost_spike_detector_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.spike_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "deviation_threshold": self._threshold,
            "spike_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
