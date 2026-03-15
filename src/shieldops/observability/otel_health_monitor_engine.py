"""OtelHealthMonitorEngine — monitor OTel Collector health via zpages and internal metrics."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class HealthIndicator(StrEnum):
    CPU_USAGE = "cpu_usage"
    MEMORY_USAGE = "memory_usage"
    QUEUE_DEPTH = "queue_depth"
    DROPPED_DATA = "dropped_data"


class CollectorStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNREACHABLE = "unreachable"


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


# --- Models ---


class OtelHealthMonitorRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    health_indicator: HealthIndicator = HealthIndicator.CPU_USAGE
    collector_status: CollectorStatus = CollectorStatus.HEALTHY
    alert_severity: AlertSeverity = AlertSeverity.INFO
    score: float = 0.0
    value: float = 0.0
    collector_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelHealthMonitorAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    health_indicator: HealthIndicator = HealthIndicator.CPU_USAGE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelHealthMonitorReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_health_indicator: dict[str, int] = Field(default_factory=dict)
    by_collector_status: dict[str, int] = Field(default_factory=dict)
    by_alert_severity: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OtelHealthMonitorEngine:
    """Monitor OTel Collector health via zpages and internal metrics."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[OtelHealthMonitorRecord] = []
        self._analyses: list[OtelHealthMonitorAnalysis] = []
        logger.info(
            "otel_health_monitor_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        health_indicator: HealthIndicator = HealthIndicator.CPU_USAGE,
        collector_status: CollectorStatus = CollectorStatus.HEALTHY,
        alert_severity: AlertSeverity = AlertSeverity.INFO,
        score: float = 0.0,
        value: float = 0.0,
        collector_id: str = "",
        service: str = "",
        team: str = "",
    ) -> OtelHealthMonitorRecord:
        record = OtelHealthMonitorRecord(
            name=name,
            health_indicator=health_indicator,
            collector_status=collector_status,
            alert_severity=alert_severity,
            score=score,
            value=value,
            collector_id=collector_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "otel_health_monitor_engine.record_added",
            record_id=record.id,
            name=name,
            health_indicator=health_indicator.value,
            collector_status=collector_status.value,
        )
        return record

    def get_record(self, record_id: str) -> OtelHealthMonitorRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        health_indicator: HealthIndicator | None = None,
        collector_status: CollectorStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[OtelHealthMonitorRecord]:
        results = list(self._records)
        if health_indicator is not None:
            results = [r for r in results if r.health_indicator == health_indicator]
        if collector_status is not None:
            results = [r for r in results if r.collector_status == collector_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        health_indicator: HealthIndicator = HealthIndicator.CPU_USAGE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> OtelHealthMonitorAnalysis:
        analysis = OtelHealthMonitorAnalysis(
            name=name,
            health_indicator=health_indicator,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "otel_health_monitor_engine.analysis_added",
            name=name,
            health_indicator=health_indicator.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def detect_unhealthy_collectors(self) -> list[dict[str, Any]]:
        """Find collectors that are degraded, unhealthy, or unreachable."""
        unhealthy: list[dict[str, Any]] = []
        collector_data: dict[str, list[OtelHealthMonitorRecord]] = {}
        for r in self._records:
            collector_data.setdefault(r.collector_id, []).append(r)
        for cid, records in collector_data.items():
            latest = records[-1]
            if latest.collector_status != CollectorStatus.HEALTHY:
                unhealthy.append(
                    {
                        "collector_id": cid,
                        "status": latest.collector_status.value,
                        "latest_score": latest.score,
                        "alert_severity": latest.alert_severity.value,
                        "sample_count": len(records),
                    }
                )
        return sorted(unhealthy, key=lambda x: x["latest_score"])

    def analyze_resource_pressure(self) -> dict[str, Any]:
        """Analyze CPU, memory, queue pressure across collectors."""
        indicator_data: dict[str, list[float]] = {}
        for r in self._records:
            indicator_data.setdefault(r.health_indicator.value, []).append(r.value)
        result: dict[str, Any] = {}
        for indicator, values in indicator_data.items():
            avg_val = sum(values) / len(values)
            max_val = max(values)
            result[indicator] = {
                "avg_value": round(avg_val, 2),
                "max_value": round(max_val, 2),
                "sample_count": len(values),
                "pressure": "high" if avg_val > self._threshold else "normal",
            }
        return result

    def recommend_scaling_actions(self) -> list[dict[str, Any]]:
        """Recommend scaling actions based on health metrics."""
        recommendations: list[dict[str, Any]] = []
        collector_data: dict[str, list[OtelHealthMonitorRecord]] = {}
        for r in self._records:
            collector_data.setdefault(r.collector_id, []).append(r)
        for cid, records in collector_data.items():
            scores = [r.score for r in records]
            avg_score = sum(scores) / len(scores)
            unhealthy_count = sum(
                1 for r in records if r.collector_status != CollectorStatus.HEALTHY
            )
            if avg_score < self._threshold or unhealthy_count > len(records) * 0.5:
                action = "scale_up" if avg_score < self._threshold * 0.5 else "investigate"
                recommendations.append(
                    {
                        "collector_id": cid,
                        "action": action,
                        "avg_score": round(avg_score, 2),
                        "unhealthy_pct": round(unhealthy_count / len(records) * 100, 1),
                        "priority": "high" if action == "scale_up" else "medium",
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
            key = r.health_indicator.value
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
                        "health_indicator": r.health_indicator.value,
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

    def generate_report(self) -> OtelHealthMonitorReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.health_indicator.value] = by_e1.get(r.health_indicator.value, 0) + 1
            by_e2[r.collector_status.value] = by_e2.get(r.collector_status.value, 0) + 1
            by_e3[r.alert_severity.value] = by_e3.get(r.alert_severity.value, 0) + 1
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
            recs.append("OTel Health Monitor Engine is healthy")
        return OtelHealthMonitorReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_health_indicator=by_e1,
            by_collector_status=by_e2,
            by_alert_severity=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("otel_health_monitor_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.health_indicator.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "health_indicator_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
