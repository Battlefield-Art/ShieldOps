"""Vault Health Analytics — track health, capacity, and recovery readiness."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class VaultMetric(StrEnum):
    INTEGRITY_CHECK = "integrity_check"
    ACCESS_LATENCY = "access_latency"
    STORAGE_USAGE = "storage_usage"
    REPLICATION_LAG = "replication_lag"
    SEAL_STATUS = "seal_status"


class HealthTrend(StrEnum):
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class CapacityForecast(StrEnum):
    SUFFICIENT = "sufficient"
    ADEQUATE = "adequate"
    APPROACHING_LIMIT = "approaching_limit"
    NEAR_CAPACITY = "near_capacity"
    EXCEEDED = "exceeded"


# --- Models ---


class VaultHealthRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vault_id: str = ""
    metric: VaultMetric = VaultMetric.INTEGRITY_CHECK
    health_trend: HealthTrend = HealthTrend.STABLE
    capacity_forecast: CapacityForecast = CapacityForecast.SUFFICIENT
    value: float = 0.0
    storage_used_pct: float = 0.0
    replication_lag_ms: float = 0.0
    recovery_time_objective_hours: float = 4.0
    created_at: float = Field(default_factory=time.time)


class VaultHealthAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vault_id: str = ""
    overall_health_score: float = 0.0
    days_until_capacity: float = 0.0
    recovery_ready: bool = True
    analyzed_at: float = Field(default_factory=time.time)


class VaultHealthReport(BaseModel):
    total_records: int = 0
    avg_storage_used_pct: float = 0.0
    degraded_count: int = 0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_health_trend: dict[str, int] = Field(default_factory=dict)
    by_capacity: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class VaultHealthAnalytics:
    """Track vault health, forecast capacity, and measure recovery."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[VaultHealthRecord] = []
        logger.info(
            "vault_health_analytics.initialized",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> VaultHealthRecord:
        record = VaultHealthRecord(**kwargs)
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "vault_health_analytics.record_added",
            record_id=record.id,
            vault_id=record.vault_id,
        )
        return record

    def process(self, key: str) -> dict[str, Any]:
        matches = [r for r in self._records if r.id == key]
        if not matches:
            return {"found": False, "key": key}
        rec = matches[0]
        return {
            "found": True,
            "id": rec.id,
            "vault_id": rec.vault_id,
            "health_trend": rec.health_trend.value,
        }

    # -- domain methods --

    def track_vault_health(self, vault_id: str = "") -> dict[str, Any]:
        """Track overall vault health."""
        records = self._records
        if vault_id:
            records = [r for r in records if r.vault_id == vault_id]
        if not records:
            return {"vault_id": vault_id, "health_score": 0.0}
        degraded = sum(
            1
            for r in records
            if r.health_trend
            in (
                HealthTrend.DEGRADING,
                HealthTrend.CRITICAL,
            )
        )
        health_score = round(1.0 - (degraded / len(records)), 4)
        avg_storage = round(
            sum(r.storage_used_pct for r in records) / len(records),
            2,
        )
        return {
            "vault_id": vault_id,
            "health_score": health_score,
            "avg_storage_used_pct": avg_storage,
            "degraded_count": degraded,
            "total_records": len(records),
        }

    def forecast_capacity(self, vault_id: str = "") -> dict[str, Any]:
        """Forecast capacity for vaults."""
        records = self._records
        if vault_id:
            records = [r for r in records if r.vault_id == vault_id]
        if not records:
            return {"vault_id": vault_id, "forecast": "unknown"}
        avg_usage = sum(r.storage_used_pct for r in records) / len(records)
        if avg_usage >= 95:
            forecast = "exceeded"
            days_remaining = 0.0
        elif avg_usage >= 85:
            forecast = "near_capacity"
            days_remaining = round((100 - avg_usage) * 3, 1)
        elif avg_usage >= 70:
            forecast = "approaching_limit"
            days_remaining = round((100 - avg_usage) * 5, 1)
        else:
            forecast = "sufficient"
            days_remaining = round((100 - avg_usage) * 10, 1)
        return {
            "vault_id": vault_id,
            "avg_storage_used_pct": round(avg_usage, 2),
            "forecast": forecast,
            "estimated_days_remaining": days_remaining,
        }

    def measure_recovery_readiness(self, vault_id: str = "") -> dict[str, Any]:
        """Measure disaster recovery readiness."""
        records = self._records
        if vault_id:
            records = [r for r in records if r.vault_id == vault_id]
        if not records:
            return {"vault_id": vault_id, "ready": False}
        avg_rto = sum(r.recovery_time_objective_hours for r in records) / len(records)
        avg_lag = sum(r.replication_lag_ms for r in records) / len(records)
        ready = avg_rto <= 8.0 and avg_lag < 5000
        return {
            "vault_id": vault_id,
            "avg_rto_hours": round(avg_rto, 2),
            "avg_replication_lag_ms": round(avg_lag, 2),
            "recovery_ready": ready,
            "total_records": len(records),
        }

    # -- report / stats --

    def generate_report(self) -> VaultHealthReport:
        by_metric: dict[str, int] = {}
        by_trend: dict[str, int] = {}
        by_cap: dict[str, int] = {}
        total_storage = 0.0
        for r in self._records:
            by_metric[r.metric.value] = by_metric.get(r.metric.value, 0) + 1
            by_trend[r.health_trend.value] = by_trend.get(r.health_trend.value, 0) + 1
            by_cap[r.capacity_forecast.value] = by_cap.get(r.capacity_forecast.value, 0) + 1
            total_storage += r.storage_used_pct
        avg_storage = round(total_storage / len(self._records), 2) if self._records else 0.0
        degraded = by_trend.get("degrading", 0) + by_trend.get("critical", 0)
        recs: list[str] = []
        if degraded > 0:
            recs.append(f"{degraded} degraded vault(s)")
        near_cap = by_cap.get("near_capacity", 0) + by_cap.get("exceeded", 0)
        if near_cap > 0:
            recs.append(f"{near_cap} vault(s) near/over capacity")
        if not recs:
            recs.append("Vault health nominal")
        return VaultHealthReport(
            total_records=len(self._records),
            avg_storage_used_pct=avg_storage,
            degraded_count=degraded,
            by_metric=by_metric,
            by_health_trend=by_trend,
            by_capacity=by_cap,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "unique_vaults": len({r.vault_id for r in self._records if r.vault_id}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("vault_health_analytics.cleared")
        return {"status": "cleared"}
