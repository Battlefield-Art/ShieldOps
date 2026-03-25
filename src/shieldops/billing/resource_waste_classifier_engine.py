"""Resource Waste Classifier Engine — classify and track resource waste across clouds."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class WasteCategory(StrEnum):
    IDLE_COMPUTE = "idle_compute"
    OVERSIZED_INSTANCE = "oversized_instance"
    UNUSED_STORAGE = "unused_storage"
    ORPHANED_RESOURCE = "orphaned_resource"
    UNATTACHED_VOLUME = "unattached_volume"


class WasteSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class ReclamationStatus(StrEnum):
    IDENTIFIED = "identified"
    APPROVED = "approved"
    RECLAIMED = "reclaimed"
    DEFERRED = "deferred"
    EXEMPTED = "exempted"


# --- Models ---


class ResourceWasteRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource_id: str = ""
    waste_category: WasteCategory = WasteCategory.IDLE_COMPUTE
    waste_severity: WasteSeverity = WasteSeverity.LOW
    reclamation_status: ReclamationStatus = ReclamationStatus.IDENTIFIED
    monthly_waste_usd: float = 0.0
    utilization_pct: float = 0.0
    days_idle: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ResourceWasteAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    waste_category: WasteCategory = WasteCategory.IDLE_COMPUTE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ResourceWasteReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_waste_category: dict[str, int] = Field(default_factory=dict)
    by_waste_severity: dict[str, int] = Field(default_factory=dict)
    by_reclamation_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ResourceWasteClassifierEngine:
    """Resource Waste Classifier Engine — classify and track resource waste."""

    def __init__(
        self,
        max_records: int = 200000,
        waste_threshold: float = 100.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = waste_threshold
        self._records: list[ResourceWasteRecord] = []
        self._analyses: list[ResourceWasteAnalysis] = []
        logger.info(
            "resource_waste_classifier_engine.initialized",
            max_records=max_records,
            waste_threshold=waste_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        resource_id: str,
        waste_category: WasteCategory = WasteCategory.IDLE_COMPUTE,
        waste_severity: WasteSeverity = WasteSeverity.LOW,
        reclamation_status: ReclamationStatus = ReclamationStatus.IDENTIFIED,
        monthly_waste_usd: float = 0.0,
        utilization_pct: float = 0.0,
        days_idle: int = 0,
        service: str = "",
        team: str = "",
    ) -> ResourceWasteRecord:
        record = ResourceWasteRecord(
            resource_id=resource_id,
            waste_category=waste_category,
            waste_severity=waste_severity,
            reclamation_status=reclamation_status,
            monthly_waste_usd=monthly_waste_usd,
            utilization_pct=utilization_pct,
            days_idle=days_idle,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "resource_waste_classifier_engine.record_added",
            record_id=record.id,
            resource_id=resource_id,
            waste_category=waste_category.value,
            waste_severity=waste_severity.value,
        )
        return record

    def get_record(self, record_id: str) -> ResourceWasteRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        waste_category: WasteCategory | None = None,
        waste_severity: WasteSeverity | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ResourceWasteRecord]:
        results = list(self._records)
        if waste_category is not None:
            results = [r for r in results if r.waste_category == waste_category]
        if waste_severity is not None:
            results = [r for r in results if r.waste_severity == waste_severity]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        waste_category: WasteCategory = WasteCategory.IDLE_COMPUTE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ResourceWasteAnalysis:
        analysis = ResourceWasteAnalysis(
            name=name,
            waste_category=waste_category,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "resource_waste_classifier_engine.analysis_added",
            name=name,
            waste_category=waste_category.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_waste_distribution(self) -> dict[str, Any]:
        cat_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.waste_category.value
            cat_data.setdefault(key, []).append(r.monthly_waste_usd)
        result: dict[str, Any] = {}
        for k, costs in cat_data.items():
            result[k] = {
                "count": len(costs),
                "total_waste_usd": round(sum(costs), 2),
                "avg_waste_usd": round(sum(costs) / len(costs), 2),
            }
        return result

    def identify_high_waste_resources(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.monthly_waste_usd >= self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "resource_id": r.resource_id,
                        "waste_category": r.waste_category.value,
                        "waste_severity": r.waste_severity.value,
                        "reclamation_status": r.reclamation_status.value,
                        "monthly_waste_usd": r.monthly_waste_usd,
                        "utilization_pct": r.utilization_pct,
                        "days_idle": r.days_idle,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["monthly_waste_usd"], reverse=True)

    def detect_reclamation_trends(self) -> dict[str, Any]:
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [a.analysis_score for a in self._analyses]
        mid = len(vals) // 2
        first_half = vals[:mid]
        second_half = vals[mid:]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        delta = round(avg_second - avg_first, 2)
        if abs(delta) < 5.0:
            trend = "stable"
        elif delta > 0:
            trend = "improving"
        else:
            trend = "degrading"
        return {
            "trend": trend,
            "delta": delta,
            "avg_first_half": round(avg_first, 2),
            "avg_second_half": round(avg_second, 2),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> ResourceWasteReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.waste_category.value] = by_e1.get(r.waste_category.value, 0) + 1
            by_e2[r.waste_severity.value] = by_e2.get(r.waste_severity.value, 0) + 1
            by_e3[r.reclamation_status.value] = by_e3.get(r.reclamation_status.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.monthly_waste_usd >= self._threshold)
        costs = [r.monthly_waste_usd for r in self._records]
        total_waste = round(sum(costs), 2) if costs else 0.0
        avg_score = round(sum(costs) / len(costs), 2) if costs else 0.0
        gap_list = self.identify_high_waste_resources()
        top_gaps = [g["resource_id"] for g in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} resource(s) above waste threshold (${self._threshold}/mo)")
        if total_waste > 0:
            recs.append(f"Total monthly waste: ${total_waste}")
        if not recs:
            recs.append("Resource Waste Classifier Engine is healthy")
        return ResourceWasteReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_waste_category=by_e1,
            by_waste_severity=by_e2,
            by_reclamation_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("resource_waste_classifier_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.waste_category.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "waste_threshold": self._threshold,
            "waste_category_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
