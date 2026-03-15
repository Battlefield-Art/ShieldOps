"""OtelPipelineThroughputEngine — Monitor and optimize OTel pipeline throughput per signal type."""

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
    TRACES = "traces"
    METRICS = "metrics"
    LOGS = "logs"


class ThroughputStatus(StrEnum):
    NORMAL = "normal"
    THROTTLED = "throttled"
    BACKPRESSURED = "backpressured"
    DROPPING = "dropping"


class BottleneckLocation(StrEnum):
    RECEIVER = "receiver"
    PROCESSOR = "processor"
    EXPORTER = "exporter"


# --- Models ---


class OtelPipelineThroughputRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    signal_type: SignalType = SignalType.TRACES
    throughput_status: ThroughputStatus = ThroughputStatus.NORMAL
    bottleneck_location: BottleneckLocation = BottleneckLocation.RECEIVER
    score: float = 0.0
    events_per_second: float = 0.0
    drop_rate: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelPipelineThroughputAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    signal_type: SignalType = SignalType.TRACES
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelPipelineThroughputReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_signal_type: dict[str, int] = Field(default_factory=dict)
    by_throughput_status: dict[str, int] = Field(default_factory=dict)
    by_bottleneck_location: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OtelPipelineThroughputEngine:
    """Monitor and optimize OTel pipeline throughput per signal type."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[OtelPipelineThroughputRecord] = []
        self._analyses: list[OtelPipelineThroughputAnalysis] = []
        logger.info(
            "otel_pipeline_throughput_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        signal_type: SignalType = SignalType.TRACES,
        throughput_status: ThroughputStatus = ThroughputStatus.NORMAL,
        bottleneck_location: BottleneckLocation = BottleneckLocation.RECEIVER,
        score: float = 0.0,
        events_per_second: float = 0.0,
        drop_rate: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> OtelPipelineThroughputRecord:
        record = OtelPipelineThroughputRecord(
            name=name,
            signal_type=signal_type,
            throughput_status=throughput_status,
            bottleneck_location=bottleneck_location,
            score=score,
            events_per_second=events_per_second,
            drop_rate=drop_rate,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "otel_pipeline_throughput_engine.record_added",
            record_id=record.id,
            name=name,
            signal_type=signal_type.value,
            throughput_status=throughput_status.value,
        )
        return record

    def get_record(self, record_id: str) -> OtelPipelineThroughputRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        signal_type: SignalType | None = None,
        throughput_status: ThroughputStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[OtelPipelineThroughputRecord]:
        results = list(self._records)
        if signal_type is not None:
            results = [r for r in results if r.signal_type == signal_type]
        if throughput_status is not None:
            results = [r for r in results if r.throughput_status == throughput_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        signal_type: SignalType = SignalType.TRACES,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> OtelPipelineThroughputAnalysis:
        analysis = OtelPipelineThroughputAnalysis(
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
            "otel_pipeline_throughput_engine.analysis_added",
            name=name,
            signal_type=signal_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_throughput_bottlenecks(self) -> list[dict[str, Any]]:
        """Identify bottlenecks in the pipeline by location and signal type."""
        location_data: dict[str, dict[str, list[float]]] = {}
        for r in self._records:
            if r.throughput_status != ThroughputStatus.NORMAL:
                loc = r.bottleneck_location.value
                sig = r.signal_type.value
                location_data.setdefault(loc, {}).setdefault(sig, []).append(r.drop_rate)
        bottlenecks: list[dict[str, Any]] = []
        for loc, signals in location_data.items():
            for sig, drop_rates in signals.items():
                avg_drop = round(sum(drop_rates) / len(drop_rates), 2)
                bottlenecks.append(
                    {
                        "location": loc,
                        "signal_type": sig,
                        "occurrence_count": len(drop_rates),
                        "avg_drop_rate": avg_drop,
                        "max_drop_rate": round(max(drop_rates), 2),
                        "severity": "critical" if avg_drop > 10 else "warning",
                    }
                )
        return sorted(bottlenecks, key=lambda x: x["avg_drop_rate"], reverse=True)

    def compute_pipeline_efficiency(self) -> list[dict[str, Any]]:
        """Compute efficiency metrics per pipeline (service + signal)."""
        pipeline_data: dict[str, list[OtelPipelineThroughputRecord]] = {}
        for r in self._records:
            key = f"{r.service}:{r.signal_type.value}"
            pipeline_data.setdefault(key, []).append(r)
        results: list[dict[str, Any]] = []
        for key, records in pipeline_data.items():
            total = len(records)
            normal = sum(1 for r in records if r.throughput_status == ThroughputStatus.NORMAL)
            avg_eps = round(sum(r.events_per_second for r in records) / total, 2) if total else 0.0
            avg_drop = round(sum(r.drop_rate for r in records) / total, 2) if total else 0.0
            results.append(
                {
                    "pipeline": key,
                    "total_samples": total,
                    "normal_pct": round(normal / total * 100, 1) if total else 0.0,
                    "avg_events_per_second": avg_eps,
                    "avg_drop_rate": avg_drop,
                    "efficiency_score": round((normal / total) * 100, 1) if total else 0.0,
                }
            )
        return sorted(results, key=lambda x: x["efficiency_score"])

    def recommend_throughput_improvements(self) -> list[dict[str, Any]]:
        """Recommend improvements based on throughput status and drop rates."""
        recommendations: list[dict[str, Any]] = []
        dropping = [r for r in self._records if r.throughput_status == ThroughputStatus.DROPPING]
        for r in dropping:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "issue": "data_dropping",
                    "priority": "critical",
                    "suggestion": (
                        f"Data loss at {r.bottleneck_location.value} (drop rate: {r.drop_rate}%)"
                    ),
                }
            )
        backpressured = [
            r for r in self._records if r.throughput_status == ThroughputStatus.BACKPRESSURED
        ]
        for r in backpressured:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "issue": "backpressure",
                    "priority": "high",
                    "suggestion": (f"Scale {r.bottleneck_location.value} to relieve backpressure"),
                }
            )
        low_score = [
            r
            for r in self._records
            if r.score < self._threshold and r.throughput_status == ThroughputStatus.NORMAL
        ]
        for r in low_score:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "issue": "low_score",
                    "priority": "medium",
                    "suggestion": f"Optimize pipeline config (score: {r.score})",
                }
            )
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        return sorted(recommendations, key=lambda x: priority_order.get(x["priority"], 3))

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

    def generate_report(self) -> OtelPipelineThroughputReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.signal_type.value] = by_e1.get(r.signal_type.value, 0) + 1
            by_e2[r.throughput_status.value] = by_e2.get(r.throughput_status.value, 0) + 1
            by_e3[r.bottleneck_location.value] = by_e3.get(r.bottleneck_location.value, 0) + 1
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
            recs.append("OTel Pipeline Throughput Engine is healthy")
        return OtelPipelineThroughputReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_signal_type=by_e1,
            by_throughput_status=by_e2,
            by_bottleneck_location=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("otel_pipeline_throughput_engine.cleared")
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
