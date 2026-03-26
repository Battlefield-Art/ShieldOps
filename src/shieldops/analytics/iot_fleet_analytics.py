"""IoT Fleet Analytics — analyze fleet health, compliance, and risk trends."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class FleetMetric(StrEnum):
    DEVICE_UPTIME = "device_uptime"
    FIRMWARE_CURRENCY = "firmware_currency"
    COMMUNICATION_HEALTH = "communication_health"
    PATCH_COMPLIANCE = "patch_compliance"
    ANOMALY_RATE = "anomaly_rate"


class ComplianceRate(StrEnum):
    FULLY_COMPLIANT = "fully_compliant"
    MOSTLY_COMPLIANT = "mostly_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"


class ThreatTrend(StrEnum):
    DECREASING = "decreasing"
    STABLE = "stable"
    INCREASING = "increasing"
    SPIKE = "spike"
    CRITICAL = "critical"


# --- Models ---


class FleetAnalyticsRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    fleet_id: str = ""
    metric: FleetMetric = FleetMetric.DEVICE_UPTIME
    compliance: ComplianceRate = ComplianceRate.UNKNOWN
    threat_trend: ThreatTrend = ThreatTrend.STABLE
    device_count: int = 0
    healthy_count: int = 0
    anomaly_count: int = 0
    value: float = 0.0
    created_at: float = Field(default_factory=time.time)


class FleetAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    fleet_id: str = ""
    health_score: float = 0.0
    compliance_score: float = 0.0
    risk_score: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class FleetAnalyticsReport(BaseModel):
    total_records: int = 0
    total_devices: int = 0
    avg_health_pct: float = 0.0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_compliance: dict[str, int] = Field(default_factory=dict)
    by_threat_trend: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class IoTFleetAnalytics:
    """Analyze IoT fleet health, compliance, and risk trends."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[FleetAnalyticsRecord] = []
        logger.info(
            "iot_fleet_analytics.initialized",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> FleetAnalyticsRecord:
        record = FleetAnalyticsRecord(**kwargs)
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "iot_fleet_analytics.record_added",
            record_id=record.id,
            fleet_id=record.fleet_id,
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
            "fleet_id": rec.fleet_id,
            "metric": rec.metric.value,
        }

    # -- domain methods --

    def analyze_fleet_health(self, fleet_id: str = "") -> dict[str, Any]:
        """Analyze health of the IoT fleet."""
        records = self._records
        if fleet_id:
            records = [r for r in records if r.fleet_id == fleet_id]
        if not records:
            return {"fleet_id": fleet_id, "health_pct": 0.0, "total": 0}
        total_devices = sum(r.device_count for r in records)
        total_healthy = sum(r.healthy_count for r in records)
        health_pct = round(total_healthy / total_devices * 100, 2) if total_devices > 0 else 0.0
        return {
            "fleet_id": fleet_id,
            "total_devices": total_devices,
            "healthy_devices": total_healthy,
            "health_pct": health_pct,
            "records_analyzed": len(records),
        }

    def track_compliance_drift(self, fleet_id: str = "") -> dict[str, Any]:
        """Track compliance drift over time."""
        records = self._records
        if fleet_id:
            records = [r for r in records if r.fleet_id == fleet_id]
        by_comp: dict[str, int] = {}
        for r in records:
            by_comp[r.compliance.value] = by_comp.get(r.compliance.value, 0) + 1
        non_compliant = by_comp.get("non_compliant", 0)
        total = len(records)
        drift_pct = round(non_compliant / total * 100, 2) if total > 0 else 0.0
        return {
            "fleet_id": fleet_id,
            "compliance_distribution": by_comp,
            "drift_pct": drift_pct,
            "total_records": total,
        }

    def predict_risk_trend(self, fleet_id: str = "") -> dict[str, Any]:
        """Predict risk trend for the fleet."""
        records = self._records
        if fleet_id:
            records = [r for r in records if r.fleet_id == fleet_id]
        by_trend: dict[str, int] = {}
        for r in records:
            by_trend[r.threat_trend.value] = by_trend.get(r.threat_trend.value, 0) + 1
        increasing = by_trend.get("increasing", 0) + by_trend.get("spike", 0)
        total = len(records)
        if total == 0:
            predicted = "stable"
        elif increasing / total > 0.5:
            predicted = "increasing"
        elif increasing / total > 0.25:
            predicted = "elevated"
        else:
            predicted = "stable"
        return {
            "fleet_id": fleet_id,
            "trend_distribution": by_trend,
            "predicted_trend": predicted,
            "total_records": total,
        }

    # -- report / stats --

    def generate_report(self) -> FleetAnalyticsReport:
        by_metric: dict[str, int] = {}
        by_comp: dict[str, int] = {}
        by_trend: dict[str, int] = {}
        total_devices = 0
        total_healthy = 0
        for r in self._records:
            by_metric[r.metric.value] = by_metric.get(r.metric.value, 0) + 1
            by_comp[r.compliance.value] = by_comp.get(r.compliance.value, 0) + 1
            by_trend[r.threat_trend.value] = by_trend.get(r.threat_trend.value, 0) + 1
            total_devices += r.device_count
            total_healthy += r.healthy_count
        avg_health = round(total_healthy / total_devices * 100, 2) if total_devices > 0 else 0.0
        recs: list[str] = []
        non_comp = by_comp.get("non_compliant", 0)
        if non_comp > 0:
            recs.append(f"{non_comp} non-compliant fleet record(s)")
        spikes = by_trend.get("spike", 0) + by_trend.get("critical", 0)
        if spikes > 0:
            recs.append(f"{spikes} threat spike(s) detected")
        if not recs:
            recs.append("IoT fleet analytics nominal")
        return FleetAnalyticsReport(
            total_records=len(self._records),
            total_devices=total_devices,
            avg_health_pct=avg_health,
            by_metric=by_metric,
            by_compliance=by_comp,
            by_threat_trend=by_trend,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "unique_fleets": len({r.fleet_id for r in self._records if r.fleet_id}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("iot_fleet_analytics.cleared")
        return {"status": "cleared"}
