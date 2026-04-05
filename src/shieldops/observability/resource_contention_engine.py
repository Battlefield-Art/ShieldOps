"""ResourceContentionEngine — Track and analyze resource contention events."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ContentionType(StrEnum):
    CPU = "cpu"
    MEMORY = "memory"
    DISK_IO = "disk_io"
    NETWORK = "network"
    LOCK = "lock"


class ContentionSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class ResolutionAction(StrEnum):
    SCALE_UP = "scale_up"
    OPTIMIZE_QUERY = "optimize_query"
    ADD_CACHE = "add_cache"
    REDUCE_CONCURRENCY = "reduce_concurrency"
    UPGRADE = "upgrade"


# --- Models ---


class ResourceContentionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    contention_type: ContentionType = ContentionType.CPU
    contention_severity: ContentionSeverity = ContentionSeverity.MEDIUM
    resolution_action: ResolutionAction = ResolutionAction.SCALE_UP
    score: float = 0.0
    utilization_pct: float = 0.0
    duration_seconds: float = 0.0
    affected_pods: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ResourceContentionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    contention_type: ContentionType = ContentionType.CPU
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ResourceContentionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_contention_type: dict[str, int] = Field(default_factory=dict)
    by_contention_severity: dict[str, int] = Field(default_factory=dict)
    by_resolution_action: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ResourceContentionEngine:
    """Track and analyze resource contention events across infrastructure."""

    def __init__(
        self,
        max_records: int = 200000,
        contention_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = contention_threshold
        self._records: list[ResourceContentionRecord] = []
        self._analyses: list[ResourceContentionAnalysis] = []
        logger.info(
            "resource_contention_engine.initialized",
            max_records=max_records,
            contention_threshold=contention_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        contention_type: ContentionType = ContentionType.CPU,
        contention_severity: ContentionSeverity = ContentionSeverity.MEDIUM,
        resolution_action: ResolutionAction = ResolutionAction.SCALE_UP,
        score: float = 0.0,
        utilization_pct: float = 0.0,
        duration_seconds: float = 0.0,
        affected_pods: int = 0,
        service: str = "",
        team: str = "",
    ) -> ResourceContentionRecord:
        record = ResourceContentionRecord(
            name=name,
            contention_type=contention_type,
            contention_severity=contention_severity,
            resolution_action=resolution_action,
            score=score,
            utilization_pct=utilization_pct,
            duration_seconds=duration_seconds,
            affected_pods=affected_pods,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "resource_contention_engine.record_added",
            record_id=record.id,
            name=name,
            contention_type=contention_type.value,
            contention_severity=contention_severity.value,
        )
        return record

    def get_record(self, record_id: str) -> ResourceContentionRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        contention_type: ContentionType | None = None,
        contention_severity: ContentionSeverity | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ResourceContentionRecord]:
        results = list(self._records)
        if contention_type is not None:
            results = [r for r in results if r.contention_type == contention_type]
        if contention_severity is not None:
            results = [r for r in results if r.contention_severity == contention_severity]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        contention_type: ContentionType = ContentionType.CPU,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ResourceContentionAnalysis:
        analysis = ResourceContentionAnalysis(
            name=name,
            contention_type=contention_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "resource_contention_engine.analysis_added",
            name=name,
            contention_type=contention_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_contention_hotspots(self) -> list[dict[str, Any]]:
        """Identify services with frequent resource contention."""
        svc_data: dict[str, list[ResourceContentionRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        hotspots: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            critical_count = sum(
                1
                for r in records
                if r.contention_severity in (ContentionSeverity.CRITICAL, ContentionSeverity.HIGH)
            )
            if critical_count > 0:
                avg_util = round(sum(r.utilization_pct for r in records) / len(records), 2)
                type_counts: dict[str, int] = {}
                for r in records:
                    t = r.contention_type.value
                    type_counts[t] = type_counts.get(t, 0) + 1
                top_type = max(type_counts, key=type_counts.get)  # type: ignore[arg-type]
                hotspots.append(
                    {
                        "service": svc,
                        "total_events": len(records),
                        "critical_events": critical_count,
                        "avg_utilization_pct": avg_util,
                        "top_contention_type": top_type,
                        "severity": (
                            "critical" if critical_count > len(records) / 2 else "warning"
                        ),
                    }
                )
        return sorted(hotspots, key=lambda x: x["critical_events"], reverse=True)

    def compute_contention_trends(self) -> list[dict[str, Any]]:
        """Compute contention trends per resource type."""
        type_records: dict[str, list[ResourceContentionRecord]] = {}
        for r in self._records:
            type_records.setdefault(r.contention_type.value, []).append(r)
        results: list[dict[str, Any]] = []
        for ctype, records in type_records.items():
            total = len(records)
            avg_util = round(sum(r.utilization_pct for r in records) / total, 2) if total else 0.0
            avg_duration = (
                round(sum(r.duration_seconds for r in records) / total, 2) if total else 0.0
            )
            above_threshold = sum(1 for r in records if r.utilization_pct > self._threshold)
            results.append(
                {
                    "contention_type": ctype,
                    "total_events": total,
                    "avg_utilization_pct": avg_util,
                    "avg_duration_seconds": avg_duration,
                    "above_threshold_count": above_threshold,
                }
            )
        return sorted(results, key=lambda x: x["above_threshold_count"], reverse=True)

    def recommend_resolution_actions(self) -> list[dict[str, Any]]:
        """Recommend resolution actions based on contention patterns."""
        recommendations: list[dict[str, Any]] = []
        critical = [
            r for r in self._records if r.contention_severity == ContentionSeverity.CRITICAL
        ]
        for r in critical:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "contention_type": r.contention_type.value,
                    "issue": "critical_contention",
                    "priority": "critical",
                    "suggestion": (
                        f"{r.resolution_action.value} for {r.service} "
                        f"({r.contention_type.value} at "
                        f"{r.utilization_pct}%)"
                    ),
                }
            )
        high_util = [
            r
            for r in self._records
            if r.utilization_pct > 90 and r.contention_severity != ContentionSeverity.CRITICAL
        ]
        for r in high_util:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "contention_type": r.contention_type.value,
                    "issue": "high_utilization",
                    "priority": "high",
                    "suggestion": (
                        f"Scale {r.service} — {r.contention_type.value} at {r.utilization_pct}%"
                    ),
                }
            )
        long_duration = [r for r in self._records if r.duration_seconds > 300]
        for r in long_duration:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "contention_type": r.contention_type.value,
                    "issue": "prolonged_contention",
                    "priority": "medium",
                    "suggestion": (
                        f"Investigate prolonged {r.contention_type.value} "
                        f"contention ({r.duration_seconds}s)"
                    ),
                }
            )
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        return sorted(recommendations, key=lambda x: priority_order.get(x["priority"], 3))

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.contention_type.value
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
            if r.utilization_pct > self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "contention_type": r.contention_type.value,
                        "utilization_pct": r.utilization_pct,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["utilization_pct"], reverse=True)

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.utilization_pct)
        results: list[dict[str, Any]] = []
        for svc, utils in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_utilization_pct": round(sum(utils) / len(utils), 2),
                }
            )
        results.sort(key=lambda x: x["avg_utilization_pct"], reverse=True)
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        utils = [r.utilization_pct for r in matched]
        avg = round(sum(utils) / len(utils), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_utilization_pct": avg,
            "above_threshold": sum(1 for u in utils if u > self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> ResourceContentionReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.contention_type.value] = by_e1.get(r.contention_type.value, 0) + 1
            by_e2[r.contention_severity.value] = by_e2.get(r.contention_severity.value, 0) + 1
            by_e3[r.resolution_action.value] = by_e3.get(r.resolution_action.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.utilization_pct > self._threshold)
        utils = [r.utilization_pct for r in self._records]
        avg_util = round(sum(utils) / len(utils), 2) if utils else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) above threshold ({self._threshold}%)")
        if self._records and avg_util > self._threshold:
            recs.append(f"Avg utilization {avg_util}% above threshold ({self._threshold}%)")
        if not recs:
            recs.append("Resource Contention Engine is healthy")
        return ResourceContentionReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_util,
            by_contention_type=by_e1,
            by_contention_severity=by_e2,
            by_resolution_action=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("resource_contention_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.contention_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "contention_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
