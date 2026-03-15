"""Telemetry Fanout Router Engine —
evaluate fanout efficiency, detect routing asymmetry,
optimize routing rules."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RoutingStrategy(StrEnum):
    BROADCAST = "broadcast"
    CONTENT_BASED = "content_based"
    ROUND_ROBIN = "round_robin"
    PRIORITY_BASED = "priority_based"


class FanoutStatus(StrEnum):
    ALL_DELIVERED = "all_delivered"
    PARTIAL_DELIVERY = "partial_delivery"
    PRIMARY_ONLY = "primary_only"
    ALL_FAILED = "all_failed"


class RoutingCriteria(StrEnum):
    SIGNAL_TYPE = "signal_type"
    SERVICE_NAME = "service_name"
    ENVIRONMENT = "environment"
    PRIORITY_LEVEL = "priority_level"


# --- Models ---


class TelemetryFanoutRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    route_id: str = ""
    routing_strategy: RoutingStrategy = RoutingStrategy.BROADCAST
    fanout_status: FanoutStatus = FanoutStatus.ALL_DELIVERED
    routing_criteria: RoutingCriteria = RoutingCriteria.SIGNAL_TYPE
    destination_count: int = 1
    delivered_count: int = 0
    items_routed: int = 0
    routing_latency_ms: float = 0.0
    asymmetry_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TelemetryFanoutAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    route_id: str = ""
    routing_strategy: RoutingStrategy = RoutingStrategy.BROADCAST
    fanout_status: FanoutStatus = FanoutStatus.ALL_DELIVERED
    delivery_ratio: float = 1.0
    asymmetry_detected: bool = False
    efficiency_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TelemetryFanoutReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_delivery_ratio: float = 0.0
    by_routing_strategy: dict[str, int] = Field(default_factory=dict)
    by_fanout_status: dict[str, int] = Field(default_factory=dict)
    by_routing_criteria: dict[str, int] = Field(default_factory=dict)
    asymmetric_routes: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class TelemetryFanoutRouterEngine:
    """Evaluate fanout efficiency, detect routing asymmetry,
    optimize routing rules."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[TelemetryFanoutRecord] = []
        self._analyses: dict[str, TelemetryFanoutAnalysis] = {}
        logger.info("telemetry_fanout_router_engine.init", max_records=max_records)

    def add_record(
        self,
        route_id: str = "",
        routing_strategy: RoutingStrategy = RoutingStrategy.BROADCAST,
        fanout_status: FanoutStatus = FanoutStatus.ALL_DELIVERED,
        routing_criteria: RoutingCriteria = RoutingCriteria.SIGNAL_TYPE,
        destination_count: int = 1,
        delivered_count: int = 0,
        items_routed: int = 0,
        routing_latency_ms: float = 0.0,
        asymmetry_score: float = 0.0,
        description: str = "",
    ) -> TelemetryFanoutRecord:
        record = TelemetryFanoutRecord(
            route_id=route_id,
            routing_strategy=routing_strategy,
            fanout_status=fanout_status,
            routing_criteria=routing_criteria,
            destination_count=destination_count,
            delivered_count=delivered_count,
            items_routed=items_routed,
            routing_latency_ms=routing_latency_ms,
            asymmetry_score=asymmetry_score,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "telemetry_fanout.record_added",
            record_id=record.id,
            route_id=route_id,
        )
        return record

    def process(self, key: str) -> TelemetryFanoutAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        delivery_ratio = round(
            (rec.delivered_count / rec.destination_count) if rec.destination_count > 0 else 0.0,
            4,
        )
        asymmetry_detected = rec.asymmetry_score > 0.3
        efficiency_score = round(
            delivery_ratio * 100.0 * (1.0 - rec.asymmetry_score),
            2,
        )
        analysis = TelemetryFanoutAnalysis(
            route_id=rec.route_id,
            routing_strategy=rec.routing_strategy,
            fanout_status=rec.fanout_status,
            delivery_ratio=delivery_ratio,
            asymmetry_detected=asymmetry_detected,
            efficiency_score=efficiency_score,
            description=(f"Route {rec.route_id} delivery ratio {delivery_ratio:.3f}"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> TelemetryFanoutReport:
        by_strategy: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_criteria: dict[str, int] = {}
        delivery_vals: list[float] = []
        asymmetric: list[str] = []
        for r in self._records:
            ks = r.routing_strategy.value
            by_strategy[ks] = by_strategy.get(ks, 0) + 1
            kf = r.fanout_status.value
            by_status[kf] = by_status.get(kf, 0) + 1
            kc = r.routing_criteria.value
            by_criteria[kc] = by_criteria.get(kc, 0) + 1
            ratio = (r.delivered_count / r.destination_count) if r.destination_count > 0 else 0.0
            delivery_vals.append(ratio)
            if r.asymmetry_score > 0.3 and r.route_id not in asymmetric:
                asymmetric.append(r.route_id)
        avg_ratio = round(sum(delivery_vals) / len(delivery_vals), 4) if delivery_vals else 0.0
        recs: list[str] = []
        if asymmetric:
            recs.append(f"{len(asymmetric)} routes with significant routing asymmetry")
        failed = by_status.get("all_failed", 0)
        if failed > 0:
            recs.append(f"{failed} total fanout failures — check destination availability")
        if not recs:
            recs.append("Telemetry fanout routing is balanced and efficient")
        return TelemetryFanoutReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_delivery_ratio=avg_ratio,
            by_routing_strategy=by_strategy,
            by_fanout_status=by_status,
            by_routing_criteria=by_criteria,
            asymmetric_routes=asymmetric[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        strategy_dist: dict[str, int] = {}
        for r in self._records:
            k = r.routing_strategy.value
            strategy_dist[k] = strategy_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "strategy_distribution": strategy_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("telemetry_fanout_router_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def evaluate_fanout_efficiency(self) -> list[dict[str, Any]]:
        """Evaluate per-route fanout delivery efficiency."""
        route_data: dict[str, list[TelemetryFanoutRecord]] = {}
        for r in self._records:
            route_data.setdefault(r.route_id, []).append(r)
        results: list[dict[str, Any]] = []
        for rid, recs in route_data.items():
            avg_ratio = sum(
                (r.delivered_count / r.destination_count) if r.destination_count > 0 else 0.0
                for r in recs
            ) / len(recs)
            avg_latency = sum(r.routing_latency_ms for r in recs) / len(recs)
            avg_asymmetry = sum(r.asymmetry_score for r in recs) / len(recs)
            efficiency = round(avg_ratio * 100.0 * (1.0 - avg_asymmetry), 2)
            results.append(
                {
                    "route_id": rid,
                    "avg_delivery_ratio": round(avg_ratio, 4),
                    "avg_latency_ms": round(avg_latency, 2),
                    "avg_asymmetry_score": round(avg_asymmetry, 4),
                    "efficiency_score": efficiency,
                    "routing_strategy": recs[-1].routing_strategy.value,
                    "samples": len(recs),
                }
            )
        results.sort(key=lambda x: x["efficiency_score"])
        return results

    def detect_routing_asymmetry(self) -> list[dict[str, Any]]:
        """Detect routes with significant load asymmetry."""
        route_data: dict[str, list[TelemetryFanoutRecord]] = {}
        for r in self._records:
            route_data.setdefault(r.route_id, []).append(r)
        results: list[dict[str, Any]] = []
        for rid, recs in route_data.items():
            avg_asym = sum(r.asymmetry_score for r in recs) / len(recs)
            max_asym = max(r.asymmetry_score for r in recs)
            if avg_asym > 0.2:
                results.append(
                    {
                        "route_id": rid,
                        "avg_asymmetry_score": round(avg_asym, 4),
                        "max_asymmetry_score": round(max_asym, 4),
                        "routing_criteria": recs[-1].routing_criteria.value,
                        "severity": "high" if avg_asym > 0.5 else "medium",
                        "samples": len(recs),
                    }
                )
        results.sort(key=lambda x: x["avg_asymmetry_score"], reverse=True)
        return results

    def optimize_routing_rules(self) -> list[dict[str, Any]]:
        """Recommend routing rule optimizations per route."""
        route_data: dict[str, list[TelemetryFanoutRecord]] = {}
        for r in self._records:
            route_data.setdefault(r.route_id, []).append(r)
        results: list[dict[str, Any]] = []
        for rid, recs in route_data.items():
            avg_ratio = sum(
                (r.delivered_count / r.destination_count) if r.destination_count > 0 else 0.0
                for r in recs
            ) / len(recs)
            avg_asym = sum(r.asymmetry_score for r in recs) / len(recs)
            avg_latency = sum(r.routing_latency_ms for r in recs) / len(recs)
            suggestions: list[str] = []
            if avg_asym > 0.3:
                suggestions.append("switch to round-robin to reduce asymmetry")
            if avg_ratio < 0.9:
                suggestions.append("add failover destinations to improve delivery ratio")
            if avg_latency > 100.0:
                suggestions.append("enable local-first routing to reduce latency")
            if suggestions:
                results.append(
                    {
                        "route_id": rid,
                        "avg_delivery_ratio": round(avg_ratio, 4),
                        "avg_asymmetry_score": round(avg_asym, 4),
                        "avg_latency_ms": round(avg_latency, 2),
                        "suggestions": suggestions,
                        "priority": "high" if avg_ratio < 0.8 else "medium",
                    }
                )
        results.sort(key=lambda x: len(x["suggestions"]), reverse=True)
        return results
