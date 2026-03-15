"""Collector Fleet Autoscaler Engine —
compute scaling decisions, detect collector hotspots,
forecast fleet capacity."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ScalingTrigger(StrEnum):
    CPU_PRESSURE = "cpu_pressure"
    MEMORY_PRESSURE = "memory_pressure"
    QUEUE_DEPTH = "queue_depth"
    THROUGHPUT_LAG = "throughput_lag"


class ScalingAction(StrEnum):
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    REBALANCE = "rebalance"
    NO_ACTION = "no_action"


class FleetHealth(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    OVERLOADED = "overloaded"
    UNDERUTILIZED = "underutilized"


# --- Models ---


class CollectorFleetRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    collector_id: str = ""
    scaling_trigger: ScalingTrigger = ScalingTrigger.CPU_PRESSURE
    scaling_action: ScalingAction = ScalingAction.NO_ACTION
    fleet_health: FleetHealth = FleetHealth.HEALTHY
    cpu_utilization: float = 0.0
    memory_utilization: float = 0.0
    queue_depth: int = 0
    throughput_lag_sec: float = 0.0
    replica_count: int = 1
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CollectorFleetAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    collector_id: str = ""
    scaling_action: ScalingAction = ScalingAction.NO_ACTION
    recommended_replicas: int = 1
    is_hotspot: bool = False
    pressure_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CollectorFleetReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_cpu_utilization: float = 0.0
    avg_memory_utilization: float = 0.0
    by_scaling_trigger: dict[str, int] = Field(default_factory=dict)
    by_scaling_action: dict[str, int] = Field(default_factory=dict)
    by_fleet_health: dict[str, int] = Field(default_factory=dict)
    hotspot_collectors: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class CollectorFleetAutoscalerEngine:
    """Compute scaling decisions, detect collector hotspots,
    forecast fleet capacity."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[CollectorFleetRecord] = []
        self._analyses: dict[str, CollectorFleetAnalysis] = {}
        logger.info("collector_fleet_autoscaler_engine.init", max_records=max_records)

    def add_record(
        self,
        collector_id: str = "",
        scaling_trigger: ScalingTrigger = ScalingTrigger.CPU_PRESSURE,
        scaling_action: ScalingAction = ScalingAction.NO_ACTION,
        fleet_health: FleetHealth = FleetHealth.HEALTHY,
        cpu_utilization: float = 0.0,
        memory_utilization: float = 0.0,
        queue_depth: int = 0,
        throughput_lag_sec: float = 0.0,
        replica_count: int = 1,
        description: str = "",
    ) -> CollectorFleetRecord:
        record = CollectorFleetRecord(
            collector_id=collector_id,
            scaling_trigger=scaling_trigger,
            scaling_action=scaling_action,
            fleet_health=fleet_health,
            cpu_utilization=cpu_utilization,
            memory_utilization=memory_utilization,
            queue_depth=queue_depth,
            throughput_lag_sec=throughput_lag_sec,
            replica_count=replica_count,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "collector_fleet.record_added",
            record_id=record.id,
            collector_id=collector_id,
        )
        return record

    def process(self, key: str) -> CollectorFleetAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        pressure_score = round(
            (rec.cpu_utilization * 0.4)
            + (rec.memory_utilization * 0.4)
            + (min(rec.queue_depth / 1000.0, 1.0) * 20.0),
            2,
        )
        is_hotspot = pressure_score > 70.0
        if pressure_score > 80.0:
            action = ScalingAction.SCALE_UP
            recommended = rec.replica_count + 2
        elif pressure_score < 20.0:
            action = ScalingAction.SCALE_DOWN
            recommended = max(1, rec.replica_count - 1)
        elif is_hotspot:
            action = ScalingAction.REBALANCE
            recommended = rec.replica_count
        else:
            action = ScalingAction.NO_ACTION
            recommended = rec.replica_count
        analysis = CollectorFleetAnalysis(
            collector_id=rec.collector_id,
            scaling_action=action,
            recommended_replicas=recommended,
            is_hotspot=is_hotspot,
            pressure_score=pressure_score,
            description=(f"Collector {rec.collector_id} pressure {pressure_score:.1f}"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> CollectorFleetReport:
        by_trigger: dict[str, int] = {}
        by_action: dict[str, int] = {}
        by_health: dict[str, int] = {}
        cpu_vals: list[float] = []
        mem_vals: list[float] = []
        hotspots: list[str] = []
        for r in self._records:
            kt = r.scaling_trigger.value
            by_trigger[kt] = by_trigger.get(kt, 0) + 1
            ka = r.scaling_action.value
            by_action[ka] = by_action.get(ka, 0) + 1
            kh = r.fleet_health.value
            by_health[kh] = by_health.get(kh, 0) + 1
            cpu_vals.append(r.cpu_utilization)
            mem_vals.append(r.memory_utilization)
            if r.fleet_health == FleetHealth.OVERLOADED and r.collector_id not in hotspots:
                hotspots.append(r.collector_id)
        avg_cpu = round(sum(cpu_vals) / len(cpu_vals), 2) if cpu_vals else 0.0
        avg_mem = round(sum(mem_vals) / len(mem_vals), 2) if mem_vals else 0.0
        recs: list[str] = []
        if hotspots:
            recs.append(f"{len(hotspots)} overloaded collectors require scaling")
        underutil = by_health.get("underutilized", 0)
        if underutil > 0:
            recs.append(f"{underutil} underutilized collectors — consider scale-down")
        if not recs:
            recs.append("Collector fleet balanced and healthy")
        return CollectorFleetReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_cpu_utilization=avg_cpu,
            avg_memory_utilization=avg_mem,
            by_scaling_trigger=by_trigger,
            by_scaling_action=by_action,
            by_fleet_health=by_health,
            hotspot_collectors=hotspots[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        health_dist: dict[str, int] = {}
        for r in self._records:
            k = r.fleet_health.value
            health_dist[k] = health_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "health_distribution": health_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("collector_fleet_autoscaler_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def compute_scaling_decision(self) -> list[dict[str, Any]]:
        """Compute per-collector scaling decisions."""
        collector_data: dict[str, list[CollectorFleetRecord]] = {}
        for r in self._records:
            collector_data.setdefault(r.collector_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, recs in collector_data.items():
            avg_cpu = sum(r.cpu_utilization for r in recs) / len(recs)
            avg_mem = sum(r.memory_utilization for r in recs) / len(recs)
            avg_queue = sum(r.queue_depth for r in recs) / len(recs)
            pressure = (avg_cpu * 0.4) + (avg_mem * 0.4) + (min(avg_queue / 1000.0, 1.0) * 20.0)
            if pressure > 80.0:
                decision = ScalingAction.SCALE_UP.value
            elif pressure < 20.0:
                decision = ScalingAction.SCALE_DOWN.value
            elif pressure > 70.0:
                decision = ScalingAction.REBALANCE.value
            else:
                decision = ScalingAction.NO_ACTION.value
            results.append(
                {
                    "collector_id": cid,
                    "avg_cpu": round(avg_cpu, 2),
                    "avg_memory": round(avg_mem, 2),
                    "avg_queue_depth": round(avg_queue, 1),
                    "pressure_score": round(pressure, 2),
                    "decision": decision,
                    "samples": len(recs),
                }
            )
        results.sort(key=lambda x: x["pressure_score"], reverse=True)
        return results

    def detect_collector_hotspots(self) -> list[dict[str, Any]]:
        """Detect collectors consistently under pressure."""
        collector_data: dict[str, list[CollectorFleetRecord]] = {}
        for r in self._records:
            collector_data.setdefault(r.collector_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, recs in collector_data.items():
            overloaded = sum(1 for r in recs if r.fleet_health == FleetHealth.OVERLOADED)
            pct = round(overloaded / len(recs) * 100.0, 1) if recs else 0.0
            if pct > 50.0:
                results.append(
                    {
                        "collector_id": cid,
                        "overloaded_pct": pct,
                        "overloaded_samples": overloaded,
                        "total_samples": len(recs),
                        "hotspot": True,
                    }
                )
        results.sort(key=lambda x: x["overloaded_pct"], reverse=True)
        return results

    def forecast_fleet_capacity(self) -> list[dict[str, Any]]:
        """Forecast future fleet capacity needs based on throughput lag trends."""
        collector_data: dict[str, list[CollectorFleetRecord]] = {}
        for r in self._records:
            collector_data.setdefault(r.collector_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, recs in collector_data.items():
            if len(recs) < 2:
                continue
            lags = [r.throughput_lag_sec for r in recs]
            lag_trend = lags[-1] - lags[0]
            avg_replicas = sum(r.replica_count for r in recs) / len(recs)
            recommended = avg_replicas
            if lag_trend > 5.0:
                recommended = avg_replicas * 1.5
            elif lag_trend < -5.0:
                recommended = max(1.0, avg_replicas * 0.8)
            results.append(
                {
                    "collector_id": cid,
                    "lag_trend_sec": round(lag_trend, 2),
                    "avg_replicas": round(avg_replicas, 1),
                    "recommended_replicas": round(recommended, 1),
                    "samples": len(recs),
                }
            )
        results.sort(key=lambda x: x["lag_trend_sec"], reverse=True)
        return results
