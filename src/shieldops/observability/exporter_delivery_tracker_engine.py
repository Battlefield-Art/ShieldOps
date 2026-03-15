"""Exporter Delivery Tracker Engine —
compute delivery reliability, detect export backpressure,
rank backends by cost efficiency."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ExporterBackend(StrEnum):
    SPLUNK = "splunk"
    DATADOG = "datadog"
    PROMETHEUS_REMOTE = "prometheus_remote"
    JAEGER = "jaeger"


class DeliveryStatus(StrEnum):
    DELIVERED = "delivered"
    RETRYING = "retrying"
    DROPPED = "dropped"
    QUEUED = "queued"


class ExportFailureReason(StrEnum):
    BACKEND_UNAVAILABLE = "backend_unavailable"
    AUTH_EXPIRED = "auth_expired"
    RATE_LIMITED = "rate_limited"
    PAYLOAD_TOO_LARGE = "payload_too_large"


# --- Models ---


class ExporterDeliveryRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    exporter_id: str = ""
    exporter_backend: ExporterBackend = ExporterBackend.SPLUNK
    delivery_status: DeliveryStatus = DeliveryStatus.DELIVERED
    failure_reason: ExportFailureReason = ExportFailureReason.BACKEND_UNAVAILABLE
    items_sent: int = 0
    items_dropped: int = 0
    queue_size: int = 0
    cost_per_million_items: float = 0.0
    latency_ms: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ExporterDeliveryAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    exporter_id: str = ""
    exporter_backend: ExporterBackend = ExporterBackend.SPLUNK
    delivery_reliability_pct: float = 0.0
    backpressure_detected: bool = False
    cost_efficiency_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ExporterDeliveryReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_reliability_pct: float = 0.0
    by_exporter_backend: dict[str, int] = Field(default_factory=dict)
    by_delivery_status: dict[str, int] = Field(default_factory=dict)
    by_failure_reason: dict[str, int] = Field(default_factory=dict)
    backpressure_exporters: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ExporterDeliveryTrackerEngine:
    """Compute delivery reliability, detect export backpressure,
    rank backends by cost efficiency."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[ExporterDeliveryRecord] = []
        self._analyses: dict[str, ExporterDeliveryAnalysis] = {}
        logger.info("exporter_delivery_tracker_engine.init", max_records=max_records)

    def add_record(
        self,
        exporter_id: str = "",
        exporter_backend: ExporterBackend = ExporterBackend.SPLUNK,
        delivery_status: DeliveryStatus = DeliveryStatus.DELIVERED,
        failure_reason: ExportFailureReason = ExportFailureReason.BACKEND_UNAVAILABLE,
        items_sent: int = 0,
        items_dropped: int = 0,
        queue_size: int = 0,
        cost_per_million_items: float = 0.0,
        latency_ms: float = 0.0,
        description: str = "",
    ) -> ExporterDeliveryRecord:
        record = ExporterDeliveryRecord(
            exporter_id=exporter_id,
            exporter_backend=exporter_backend,
            delivery_status=delivery_status,
            failure_reason=failure_reason,
            items_sent=items_sent,
            items_dropped=items_dropped,
            queue_size=queue_size,
            cost_per_million_items=cost_per_million_items,
            latency_ms=latency_ms,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "exporter_delivery.record_added",
            record_id=record.id,
            exporter_id=exporter_id,
        )
        return record

    def process(self, key: str) -> ExporterDeliveryAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        total = rec.items_sent + rec.items_dropped
        reliability_pct = round(
            (rec.items_sent / total * 100.0) if total > 0 else 100.0,
            2,
        )
        backpressure = rec.queue_size > 10000 or rec.delivery_status in (
            DeliveryStatus.RETRYING,
            DeliveryStatus.QUEUED,
        )
        cost_eff = round(
            reliability_pct / max(rec.cost_per_million_items, 0.01),
            4,
        )
        analysis = ExporterDeliveryAnalysis(
            exporter_id=rec.exporter_id,
            exporter_backend=rec.exporter_backend,
            delivery_reliability_pct=reliability_pct,
            backpressure_detected=backpressure,
            cost_efficiency_score=cost_eff,
            description=(f"Exporter {rec.exporter_id} reliability {reliability_pct:.1f}%"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ExporterDeliveryReport:
        by_backend: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_failure: dict[str, int] = {}
        reliability_vals: list[float] = []
        backpressure_exporters: list[str] = []
        for r in self._records:
            kb = r.exporter_backend.value
            by_backend[kb] = by_backend.get(kb, 0) + 1
            ks = r.delivery_status.value
            by_status[ks] = by_status.get(ks, 0) + 1
            kf = r.failure_reason.value
            by_failure[kf] = by_failure.get(kf, 0) + 1
            total = r.items_sent + r.items_dropped
            rel = (r.items_sent / total * 100.0) if total > 0 else 100.0
            reliability_vals.append(rel)
            if r.queue_size > 10000 and r.exporter_id not in backpressure_exporters:
                backpressure_exporters.append(r.exporter_id)
        avg_rel = (
            round(sum(reliability_vals) / len(reliability_vals), 2) if reliability_vals else 0.0
        )
        recs: list[str] = []
        if backpressure_exporters:
            recs.append(f"{len(backpressure_exporters)} exporters with queue backpressure")
        dropped = by_status.get("dropped", 0)
        if dropped > 0:
            recs.append(f"{dropped} records with dropped status — check backend health")
        if not recs:
            recs.append("All exporters delivering data reliably")
        return ExporterDeliveryReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_reliability_pct=avg_rel,
            by_exporter_backend=by_backend,
            by_delivery_status=by_status,
            by_failure_reason=by_failure,
            backpressure_exporters=backpressure_exporters[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        status_dist: dict[str, int] = {}
        for r in self._records:
            k = r.delivery_status.value
            status_dist[k] = status_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "status_distribution": status_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("exporter_delivery_tracker_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def compute_delivery_reliability(self) -> list[dict[str, Any]]:
        """Compute delivery reliability per exporter."""
        exporter_data: dict[str, list[ExporterDeliveryRecord]] = {}
        for r in self._records:
            exporter_data.setdefault(r.exporter_id, []).append(r)
        results: list[dict[str, Any]] = []
        for eid, recs in exporter_data.items():
            total_sent = sum(r.items_sent for r in recs)
            total_dropped = sum(r.items_dropped for r in recs)
            total = total_sent + total_dropped
            reliability = round((total_sent / total * 100.0) if total > 0 else 100.0, 2)
            results.append(
                {
                    "exporter_id": eid,
                    "reliability_pct": reliability,
                    "total_sent": total_sent,
                    "total_dropped": total_dropped,
                    "samples": len(recs),
                }
            )
        results.sort(key=lambda x: x["reliability_pct"])
        return results

    def detect_export_backpressure(self) -> list[dict[str, Any]]:
        """Detect exporters experiencing queue backpressure."""
        exporter_data: dict[str, list[ExporterDeliveryRecord]] = {}
        for r in self._records:
            exporter_data.setdefault(r.exporter_id, []).append(r)
        results: list[dict[str, Any]] = []
        for eid, recs in exporter_data.items():
            avg_queue = sum(r.queue_size for r in recs) / len(recs)
            retrying = sum(1 for r in recs if r.delivery_status == DeliveryStatus.RETRYING)
            if avg_queue > 5000 or retrying > 0:
                results.append(
                    {
                        "exporter_id": eid,
                        "avg_queue_size": round(avg_queue, 0),
                        "retrying_samples": retrying,
                        "backpressure_level": "high" if avg_queue > 10000 else "medium",
                        "samples": len(recs),
                    }
                )
        results.sort(key=lambda x: x["avg_queue_size"], reverse=True)
        return results

    def rank_backends_by_cost_efficiency(self) -> list[dict[str, Any]]:
        """Rank exporter backends by cost efficiency ratio."""
        backend_data: dict[str, list[ExporterDeliveryRecord]] = {}
        for r in self._records:
            backend_data.setdefault(r.exporter_backend.value, []).append(r)
        results: list[dict[str, Any]] = []
        for backend, recs in backend_data.items():
            total_sent = sum(r.items_sent for r in recs)
            total_dropped = sum(r.items_dropped for r in recs)
            total = total_sent + total_dropped
            reliability = (total_sent / total * 100.0) if total > 0 else 100.0
            avg_cost = sum(r.cost_per_million_items for r in recs) / len(recs)
            efficiency = round(reliability / max(avg_cost, 0.01), 4)
            results.append(
                {
                    "backend": backend,
                    "reliability_pct": round(reliability, 2),
                    "avg_cost_per_million": round(avg_cost, 4),
                    "cost_efficiency_score": efficiency,
                    "samples": len(recs),
                    "rank": 0,
                }
            )
        results.sort(key=lambda x: x["cost_efficiency_score"], reverse=True)
        for idx, entry in enumerate(results, 1):
            entry["rank"] = idx
        return results
