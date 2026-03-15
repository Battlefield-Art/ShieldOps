"""Receiver Pipeline Stage Engine —
analyze receiver acceptance rate, detect receiver saturation,
compare receiver efficiency."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ReceiverType(StrEnum):
    OTLP_GRPC = "otlp_grpc"
    OTLP_HTTP = "otlp_http"
    PROMETHEUS = "prometheus"
    KAFKA = "kafka"


class ReceiverHealth(StrEnum):
    ACCEPTING = "accepting"
    THROTTLED = "throttled"
    REJECTING = "rejecting"
    DISCONNECTED = "disconnected"


class IngestionPattern(StrEnum):
    STEADY = "steady"
    BURSTY = "bursty"
    DECLINING = "declining"
    INTERMITTENT = "intermittent"


# --- Models ---


class ReceiverPipelineRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    receiver_id: str = ""
    receiver_type: ReceiverType = ReceiverType.OTLP_GRPC
    receiver_health: ReceiverHealth = ReceiverHealth.ACCEPTING
    ingestion_pattern: IngestionPattern = IngestionPattern.STEADY
    accepted_per_sec: float = 0.0
    rejected_per_sec: float = 0.0
    throttle_pct: float = 0.0
    latency_ms: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ReceiverPipelineAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    receiver_id: str = ""
    receiver_health: ReceiverHealth = ReceiverHealth.ACCEPTING
    acceptance_rate: float = 0.0
    saturated: bool = False
    efficiency_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ReceiverPipelineReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_accepted_per_sec: float = 0.0
    avg_rejected_per_sec: float = 0.0
    by_receiver_type: dict[str, int] = Field(default_factory=dict)
    by_receiver_health: dict[str, int] = Field(default_factory=dict)
    by_ingestion_pattern: dict[str, int] = Field(default_factory=dict)
    saturated_receivers: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ReceiverPipelineStageEngine:
    """Analyze receiver acceptance rate, detect receiver saturation,
    compare receiver efficiency."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[ReceiverPipelineRecord] = []
        self._analyses: dict[str, ReceiverPipelineAnalysis] = {}
        logger.info("receiver_pipeline_stage_engine.init", max_records=max_records)

    def add_record(
        self,
        receiver_id: str = "",
        receiver_type: ReceiverType = ReceiverType.OTLP_GRPC,
        receiver_health: ReceiverHealth = ReceiverHealth.ACCEPTING,
        ingestion_pattern: IngestionPattern = IngestionPattern.STEADY,
        accepted_per_sec: float = 0.0,
        rejected_per_sec: float = 0.0,
        throttle_pct: float = 0.0,
        latency_ms: float = 0.0,
        description: str = "",
    ) -> ReceiverPipelineRecord:
        record = ReceiverPipelineRecord(
            receiver_id=receiver_id,
            receiver_type=receiver_type,
            receiver_health=receiver_health,
            ingestion_pattern=ingestion_pattern,
            accepted_per_sec=accepted_per_sec,
            rejected_per_sec=rejected_per_sec,
            throttle_pct=throttle_pct,
            latency_ms=latency_ms,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "receiver_pipeline.record_added",
            record_id=record.id,
            receiver_id=receiver_id,
        )
        return record

    def process(self, key: str) -> ReceiverPipelineAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        total = rec.accepted_per_sec + rec.rejected_per_sec
        acceptance_rate = round(
            (rec.accepted_per_sec / total * 100.0) if total > 0 else 100.0,
            2,
        )
        saturated = rec.throttle_pct > 80.0 or rec.receiver_health in (
            ReceiverHealth.THROTTLED,
            ReceiverHealth.REJECTING,
        )
        efficiency_score = round(
            acceptance_rate * (1.0 - rec.throttle_pct / 100.0),
            2,
        )
        analysis = ReceiverPipelineAnalysis(
            receiver_id=rec.receiver_id,
            receiver_health=rec.receiver_health,
            acceptance_rate=acceptance_rate,
            saturated=saturated,
            efficiency_score=efficiency_score,
            description=(f"Receiver {rec.receiver_id} acceptance {acceptance_rate:.1f}%"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ReceiverPipelineReport:
        by_type: dict[str, int] = {}
        by_health: dict[str, int] = {}
        by_pattern: dict[str, int] = {}
        acc_vals: list[float] = []
        rej_vals: list[float] = []
        saturated: list[str] = []
        for r in self._records:
            kt = r.receiver_type.value
            by_type[kt] = by_type.get(kt, 0) + 1
            kh = r.receiver_health.value
            by_health[kh] = by_health.get(kh, 0) + 1
            kp = r.ingestion_pattern.value
            by_pattern[kp] = by_pattern.get(kp, 0) + 1
            acc_vals.append(r.accepted_per_sec)
            rej_vals.append(r.rejected_per_sec)
            if r.throttle_pct > 80.0 and r.receiver_id not in saturated:
                saturated.append(r.receiver_id)
        avg_acc = round(sum(acc_vals) / len(acc_vals), 2) if acc_vals else 0.0
        avg_rej = round(sum(rej_vals) / len(rej_vals), 2) if rej_vals else 0.0
        recs: list[str] = []
        if saturated:
            recs.append(f"{len(saturated)} receivers approaching saturation")
        rejecting = by_health.get("rejecting", 0)
        if rejecting > 0:
            recs.append(f"{rejecting} receivers actively rejecting data")
        if not recs:
            recs.append("All receivers operating within capacity")
        return ReceiverPipelineReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_accepted_per_sec=avg_acc,
            avg_rejected_per_sec=avg_rej,
            by_receiver_type=by_type,
            by_receiver_health=by_health,
            by_ingestion_pattern=by_pattern,
            saturated_receivers=saturated[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        health_dist: dict[str, int] = {}
        for r in self._records:
            k = r.receiver_health.value
            health_dist[k] = health_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "health_distribution": health_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("receiver_pipeline_stage_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def analyze_receiver_acceptance_rate(self) -> list[dict[str, Any]]:
        """Analyze acceptance rate per receiver."""
        receiver_data: dict[str, list[ReceiverPipelineRecord]] = {}
        for r in self._records:
            receiver_data.setdefault(r.receiver_id, []).append(r)
        results: list[dict[str, Any]] = []
        for rid, recs in receiver_data.items():
            total_acc = sum(r.accepted_per_sec for r in recs)
            total_rej = sum(r.rejected_per_sec for r in recs)
            total = total_acc + total_rej
            rate = round((total_acc / total * 100.0) if total > 0 else 100.0, 2)
            results.append(
                {
                    "receiver_id": rid,
                    "acceptance_rate_pct": rate,
                    "avg_accepted_per_sec": round(total_acc / len(recs), 2),
                    "avg_rejected_per_sec": round(total_rej / len(recs), 2),
                    "samples": len(recs),
                }
            )
        results.sort(key=lambda x: x["acceptance_rate_pct"])
        return results

    def detect_receiver_saturation(self) -> list[dict[str, Any]]:
        """Detect receivers at or near saturation."""
        receiver_data: dict[str, list[ReceiverPipelineRecord]] = {}
        for r in self._records:
            receiver_data.setdefault(r.receiver_id, []).append(r)
        results: list[dict[str, Any]] = []
        for rid, recs in receiver_data.items():
            avg_throttle = sum(r.throttle_pct for r in recs) / len(recs)
            saturated_samples = sum(
                1
                for r in recs
                if r.receiver_health in (ReceiverHealth.THROTTLED, ReceiverHealth.REJECTING)
            )
            if avg_throttle > 50.0 or saturated_samples > 0:
                results.append(
                    {
                        "receiver_id": rid,
                        "avg_throttle_pct": round(avg_throttle, 2),
                        "saturated_samples": saturated_samples,
                        "total_samples": len(recs),
                        "saturation_risk": "high" if avg_throttle > 80.0 else "medium",
                    }
                )
        results.sort(key=lambda x: x["avg_throttle_pct"], reverse=True)
        return results

    def compare_receiver_efficiency(self) -> list[dict[str, Any]]:
        """Compare efficiency across receiver types."""
        type_data: dict[str, list[ReceiverPipelineRecord]] = {}
        for r in self._records:
            type_data.setdefault(r.receiver_type.value, []).append(r)
        results: list[dict[str, Any]] = []
        for rtype, recs in type_data.items():
            avg_acc = sum(r.accepted_per_sec for r in recs) / len(recs)
            avg_lat = sum(r.latency_ms for r in recs) / len(recs)
            avg_throttle = sum(r.throttle_pct for r in recs) / len(recs)
            efficiency = round(avg_acc / max(avg_lat, 0.001) * (1.0 - avg_throttle / 100.0), 4)
            results.append(
                {
                    "receiver_type": rtype,
                    "avg_accepted_per_sec": round(avg_acc, 2),
                    "avg_latency_ms": round(avg_lat, 2),
                    "avg_throttle_pct": round(avg_throttle, 2),
                    "efficiency_score": efficiency,
                    "samples": len(recs),
                }
            )
        results.sort(key=lambda x: x["efficiency_score"], reverse=True)
        return results
