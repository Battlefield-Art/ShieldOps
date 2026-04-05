"""Failover Readiness Engine — track failover readiness across services."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ReadinessLevel(StrEnum):
    READY = "ready"
    PARTIALLY_READY = "partially_ready"
    NOT_READY = "not_ready"
    UNTESTED = "untested"
    DEGRADED = "degraded"


class FailoverComponent(StrEnum):
    DATABASE = "database"
    APPLICATION = "application"
    LOADBALANCER = "loadbalancer"
    DNS = "dns"
    STORAGE = "storage"


class ValidationFrequency(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUAL = "annual"


# --- Models ---


class FailoverReadinessRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str = ""
    readiness_level: ReadinessLevel = ReadinessLevel.UNTESTED
    failover_component: FailoverComponent = FailoverComponent.APPLICATION
    validation_frequency: ValidationFrequency = ValidationFrequency.MONTHLY
    last_validated_at: float = 0.0
    failover_time_seconds: float = 0.0
    target_failover_seconds: float = 0.0
    replication_lag_ms: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class FailoverReadinessAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str = ""
    analysis_score: float = 0.0
    readiness_level: ReadinessLevel = ReadinessLevel.UNTESTED
    components_ready: int = 0
    data_points: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class FailoverReadinessReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    readiness_rate: float = 0.0
    by_readiness: dict[str, int] = Field(default_factory=dict)
    by_component: dict[str, int] = Field(default_factory=dict)
    by_frequency: dict[str, int] = Field(default_factory=dict)
    not_ready_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class FailoverReadinessEngine:
    """Track failover readiness across services and components."""

    def __init__(
        self,
        max_records: int = 200000,
        readiness_threshold: float = 85.0,
    ) -> None:
        self._max_records = max_records
        self._readiness_threshold = readiness_threshold
        self._records: list[FailoverReadinessRecord] = []
        self._analyses: dict[str, FailoverReadinessAnalysis] = {}
        logger.info(
            "failover_readiness_engine.init",
            max_records=max_records,
            readiness_threshold=readiness_threshold,
        )

    def add_record(
        self,
        service_id: str = "",
        readiness_level: ReadinessLevel = ReadinessLevel.UNTESTED,
        failover_component: FailoverComponent = FailoverComponent.APPLICATION,
        validation_frequency: ValidationFrequency = ValidationFrequency.MONTHLY,
        last_validated_at: float = 0.0,
        failover_time_seconds: float = 0.0,
        target_failover_seconds: float = 0.0,
        replication_lag_ms: float = 0.0,
        description: str = "",
    ) -> FailoverReadinessRecord:
        record = FailoverReadinessRecord(
            service_id=service_id,
            readiness_level=readiness_level,
            failover_component=failover_component,
            validation_frequency=validation_frequency,
            last_validated_at=last_validated_at,
            failover_time_seconds=failover_time_seconds,
            target_failover_seconds=target_failover_seconds,
            replication_lag_ms=replication_lag_ms,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "failover_readiness_engine.record_added",
            record_id=record.id,
            service_id=service_id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> FailoverReadinessAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        points = sum(1 for r in self._records if r.service_id == rec.service_id)
        ready_count = sum(
            1
            for r in self._records
            if r.service_id == rec.service_id and r.readiness_level == ReadinessLevel.READY
        )
        score = round(ready_count / points * 100, 2) if points else 0.0
        analysis = FailoverReadinessAnalysis(
            service_id=rec.service_id,
            analysis_score=score,
            readiness_level=rec.readiness_level,
            components_ready=ready_count,
            data_points=points,
            description=(f"Failover readiness {score}% for {rec.service_id}"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> FailoverReadinessReport:
        by_r: dict[str, int] = {}
        by_c: dict[str, int] = {}
        by_f: dict[str, int] = {}
        ready_count = 0
        for r in self._records:
            by_r[r.readiness_level.value] = by_r.get(r.readiness_level.value, 0) + 1
            by_c[r.failover_component.value] = by_c.get(r.failover_component.value, 0) + 1
            by_f[r.validation_frequency.value] = by_f.get(r.validation_frequency.value, 0) + 1
            if r.readiness_level == ReadinessLevel.READY:
                ready_count += 1
        total = len(self._records)
        rate = round(ready_count / total * 100, 2) if total else 0.0
        not_ready = list(
            {
                r.service_id
                for r in self._records
                if r.readiness_level in (ReadinessLevel.NOT_READY, ReadinessLevel.UNTESTED)
            }
        )[:10]
        recs: list[str] = []
        if rate < self._readiness_threshold:
            recs.append(f"Readiness {rate}% below threshold {self._readiness_threshold}%")
        if not_ready:
            recs.append(f"{len(not_ready)} services not ready for failover")
        if not recs:
            recs.append("Failover readiness healthy across all services")
        return FailoverReadinessReport(
            total_records=total,
            total_analyses=len(self._analyses),
            readiness_rate=rate,
            by_readiness=by_r,
            by_component=by_c,
            by_frequency=by_f,
            not_ready_services=not_ready,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        comp_dist: dict[str, int] = {}
        for r in self._records:
            k = r.failover_component.value
            comp_dist[k] = comp_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "readiness_threshold": self._readiness_threshold,
            "component_distribution": comp_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("failover_readiness_engine.cleared")
        return {"status": "cleared"}

    # -- domain methods ---

    def assess_component_readiness(self) -> list[dict[str, Any]]:
        """Assess readiness per failover component type."""
        comp_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            k = r.failover_component.value
            comp_data.setdefault(k, {"ready": 0, "total": 0})
            comp_data[k]["total"] += 1
            if r.readiness_level == ReadinessLevel.READY:
                comp_data[k]["ready"] += 1
        results: list[dict[str, Any]] = []
        for comp, data in comp_data.items():
            rate = round(data["ready"] / data["total"] * 100, 2) if data["total"] else 0.0
            results.append(
                {
                    "component": comp,
                    "readiness_pct": rate,
                    "ready_count": data["ready"],
                    "total_count": data["total"],
                }
            )
        results.sort(key=lambda x: x["readiness_pct"])
        return results

    def detect_stale_validations(
        self,
        max_age_days: int = 90,
    ) -> list[dict[str, Any]]:
        """Detect services with stale failover validations."""
        cutoff = time.time() - (max_age_days * 86400)
        results: list[dict[str, Any]] = []
        seen: set[str] = set()
        for r in self._records:
            if r.service_id not in seen and r.last_validated_at < cutoff:
                seen.add(r.service_id)
                age_days = round((time.time() - r.last_validated_at) / 86400, 1)
                results.append(
                    {
                        "service_id": r.service_id,
                        "component": r.failover_component.value,
                        "last_validated_days_ago": age_days,
                        "validation_frequency": (r.validation_frequency.value),
                    }
                )
        results.sort(key=lambda x: x["last_validated_days_ago"], reverse=True)
        return results

    def compute_failover_time_compliance(self) -> list[dict[str, Any]]:
        """Compute failover time vs target per service."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.target_failover_seconds > 0:
                ratio = round(r.failover_time_seconds / r.target_failover_seconds, 2)
                compliant = ratio <= 1.0
                results.append(
                    {
                        "service_id": r.service_id,
                        "component": r.failover_component.value,
                        "actual_seconds": r.failover_time_seconds,
                        "target_seconds": r.target_failover_seconds,
                        "ratio": ratio,
                        "compliant": compliant,
                    }
                )
        results.sort(key=lambda x: x["ratio"], reverse=True)
        return results
