"""Collector Resource Limiter Engine —
predict OOM risk, evaluate limit headroom,
recommend resource allocation."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ResourceType(StrEnum):
    MEMORY_RSS = "memory_rss"
    CPU_CORES = "cpu_cores"
    DISK_BUFFER = "disk_buffer"
    NETWORK_BANDWIDTH = "network_bandwidth"


class LimitStatus(StrEnum):
    WITHIN_BUDGET = "within_budget"
    APPROACHING_LIMIT = "approaching_limit"
    AT_LIMIT = "at_limit"
    EXCEEDED = "exceeded"


class MitigationAction(StrEnum):
    INCREASE_SAMPLING = "increase_sampling"
    DROP_LOW_PRIORITY = "drop_low_priority"
    FLUSH_BUFFER = "flush_buffer"
    RESTART_COLLECTOR = "restart_collector"


# --- Models ---


class CollectorResourceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    collector_id: str = ""
    resource_type: ResourceType = ResourceType.MEMORY_RSS
    limit_status: LimitStatus = LimitStatus.WITHIN_BUDGET
    mitigation_action: MitigationAction = MitigationAction.INCREASE_SAMPLING
    current_usage: float = 0.0
    limit_value: float = 0.0
    usage_trend_pct_per_hour: float = 0.0
    restart_count: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CollectorResourceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    collector_id: str = ""
    resource_type: ResourceType = ResourceType.MEMORY_RSS
    limit_status: LimitStatus = LimitStatus.WITHIN_BUDGET
    headroom_pct: float = 100.0
    oom_risk: bool = False
    hours_to_limit: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CollectorResourceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_headroom_pct: float = 0.0
    by_resource_type: dict[str, int] = Field(default_factory=dict)
    by_limit_status: dict[str, int] = Field(default_factory=dict)
    by_mitigation_action: dict[str, int] = Field(default_factory=dict)
    at_risk_collectors: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class CollectorResourceLimiterEngine:
    """Predict OOM risk, evaluate limit headroom,
    recommend resource allocation."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[CollectorResourceRecord] = []
        self._analyses: dict[str, CollectorResourceAnalysis] = {}
        logger.info("collector_resource_limiter_engine.init", max_records=max_records)

    def add_record(
        self,
        collector_id: str = "",
        resource_type: ResourceType = ResourceType.MEMORY_RSS,
        limit_status: LimitStatus = LimitStatus.WITHIN_BUDGET,
        mitigation_action: MitigationAction = MitigationAction.INCREASE_SAMPLING,
        current_usage: float = 0.0,
        limit_value: float = 0.0,
        usage_trend_pct_per_hour: float = 0.0,
        restart_count: int = 0,
        description: str = "",
    ) -> CollectorResourceRecord:
        record = CollectorResourceRecord(
            collector_id=collector_id,
            resource_type=resource_type,
            limit_status=limit_status,
            mitigation_action=mitigation_action,
            current_usage=current_usage,
            limit_value=limit_value,
            usage_trend_pct_per_hour=usage_trend_pct_per_hour,
            restart_count=restart_count,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "collector_resource.record_added",
            record_id=record.id,
            collector_id=collector_id,
        )
        return record

    def process(self, key: str) -> CollectorResourceAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        headroom_pct = round(
            ((rec.limit_value - rec.current_usage) / rec.limit_value * 100.0)
            if rec.limit_value > 0
            else 100.0,
            2,
        )
        oom_risk = rec.resource_type == ResourceType.MEMORY_RSS and rec.limit_status in (
            LimitStatus.AT_LIMIT,
            LimitStatus.EXCEEDED,
        )
        remaining = rec.limit_value - rec.current_usage
        if rec.usage_trend_pct_per_hour > 0 and rec.limit_value > 0:
            hours_to_limit = round(
                (remaining / rec.limit_value * 100.0) / rec.usage_trend_pct_per_hour,
                2,
            )
        else:
            hours_to_limit = 999.0
        analysis = CollectorResourceAnalysis(
            collector_id=rec.collector_id,
            resource_type=rec.resource_type,
            limit_status=rec.limit_status,
            headroom_pct=headroom_pct,
            oom_risk=oom_risk,
            hours_to_limit=hours_to_limit,
            description=(f"Collector {rec.collector_id} headroom {headroom_pct:.1f}%"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> CollectorResourceReport:
        by_resource: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_mitigation: dict[str, int] = {}
        headroom_vals: list[float] = []
        at_risk: list[str] = []
        for r in self._records:
            kr = r.resource_type.value
            by_resource[kr] = by_resource.get(kr, 0) + 1
            ks = r.limit_status.value
            by_status[ks] = by_status.get(ks, 0) + 1
            km = r.mitigation_action.value
            by_mitigation[km] = by_mitigation.get(km, 0) + 1
            headroom = (
                ((r.limit_value - r.current_usage) / r.limit_value * 100.0)
                if r.limit_value > 0
                else 100.0
            )
            headroom_vals.append(headroom)
            if (
                r.limit_status in (LimitStatus.AT_LIMIT, LimitStatus.EXCEEDED)
                and r.collector_id not in at_risk
            ):
                at_risk.append(r.collector_id)
        avg_headroom = round(sum(headroom_vals) / len(headroom_vals), 2) if headroom_vals else 0.0
        recs: list[str] = []
        if at_risk:
            recs.append(f"{len(at_risk)} collectors at or exceeding resource limits")
        exceeded = by_status.get("exceeded", 0)
        if exceeded > 0:
            recs.append(f"{exceeded} records show limit exceeded — consider restart")
        if not recs:
            recs.append("All collectors operating within resource budgets")
        return CollectorResourceReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_headroom_pct=avg_headroom,
            by_resource_type=by_resource,
            by_limit_status=by_status,
            by_mitigation_action=by_mitigation,
            at_risk_collectors=at_risk[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        status_dist: dict[str, int] = {}
        for r in self._records:
            k = r.limit_status.value
            status_dist[k] = status_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "limit_status_distribution": status_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("collector_resource_limiter_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def predict_oom_risk(self) -> list[dict[str, Any]]:
        """Predict OOM risk per collector based on memory trends."""
        collector_data: dict[str, list[CollectorResourceRecord]] = {}
        for r in self._records:
            if r.resource_type == ResourceType.MEMORY_RSS:
                collector_data.setdefault(r.collector_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, recs in collector_data.items():
            avg_trend = sum(r.usage_trend_pct_per_hour for r in recs) / len(recs)
            avg_headroom = sum(
                ((r.limit_value - r.current_usage) / r.limit_value * 100.0)
                if r.limit_value > 0
                else 100.0
                for r in recs
            ) / len(recs)
            restart_total = sum(r.restart_count for r in recs)
            hours_to_oom = round(
                (avg_headroom / avg_trend) if avg_trend > 0 else 999.0,
                2,
            )
            results.append(
                {
                    "collector_id": cid,
                    "avg_headroom_pct": round(avg_headroom, 2),
                    "avg_trend_pct_per_hour": round(avg_trend, 4),
                    "hours_to_oom": hours_to_oom,
                    "restart_count": restart_total,
                    "oom_risk": "high" if hours_to_oom < 4.0 else "low",
                    "samples": len(recs),
                }
            )
        results.sort(key=lambda x: x["hours_to_oom"])
        return results

    def evaluate_limit_headroom(self) -> list[dict[str, Any]]:
        """Evaluate resource headroom per collector and resource type."""
        collector_data: dict[tuple[str, str], list[CollectorResourceRecord]] = {}
        for r in self._records:
            collector_data.setdefault((r.collector_id, r.resource_type.value), []).append(r)
        results: list[dict[str, Any]] = []
        for (cid, rtype), recs in collector_data.items():
            avg_headroom = sum(
                ((r.limit_value - r.current_usage) / r.limit_value * 100.0)
                if r.limit_value > 0
                else 100.0
                for r in recs
            ) / len(recs)
            results.append(
                {
                    "collector_id": cid,
                    "resource_type": rtype,
                    "avg_headroom_pct": round(avg_headroom, 2),
                    "status": "critical"
                    if avg_headroom < 10.0
                    else ("warning" if avg_headroom < 25.0 else "healthy"),
                    "samples": len(recs),
                }
            )
        results.sort(key=lambda x: x["avg_headroom_pct"])
        return results

    def recommend_resource_allocation(self) -> list[dict[str, Any]]:
        """Recommend resource limit adjustments per collector."""
        collector_data: dict[str, list[CollectorResourceRecord]] = {}
        for r in self._records:
            collector_data.setdefault(r.collector_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, recs in collector_data.items():
            by_type: dict[str, list[CollectorResourceRecord]] = {}
            for r in recs:
                by_type.setdefault(r.resource_type.value, []).append(r)
            recommendations: list[str] = []
            for rtype, type_recs in by_type.items():
                avg_headroom = sum(
                    ((r.limit_value - r.current_usage) / r.limit_value * 100.0)
                    if r.limit_value > 0
                    else 100.0
                    for r in type_recs
                ) / len(type_recs)
                if avg_headroom < 15.0:
                    recommendations.append(f"increase {rtype} limit by 50%")
                elif avg_headroom > 80.0:
                    recommendations.append(f"reduce {rtype} limit by 25% to save cost")
            if recommendations:
                results.append(
                    {
                        "collector_id": cid,
                        "recommendations": recommendations,
                        "urgency": (
                            "high" if any("increase" in r for r in recommendations) else "low"
                        ),
                    }
                )
        results.sort(key=lambda x: len(x["recommendations"]), reverse=True)
        return results
