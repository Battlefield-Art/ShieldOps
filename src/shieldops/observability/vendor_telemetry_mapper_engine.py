"""Vendor Telemetry Mapper Engine — track and optimize vendor-to-OCSF field mapping accuracy."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MappingType(StrEnum):
    DIRECT = "direct"
    TRANSFORM = "transform"
    COMPUTED = "computed"
    DEFAULT = "default"
    UNMAPPED = "unmapped"


class FieldCategory(StrEnum):
    IDENTITY = "identity"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    CLOUD = "cloud"
    APPLICATION = "application"
    METADATA = "metadata"


class MappingAccuracy(StrEnum):
    EXACT = "exact"
    APPROXIMATE = "approximate"
    LOSSY = "lossy"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


# --- Models ---


class MappingRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vendor_field: str = ""
    ocsf_field: str = ""
    mapping_type: MappingType = MappingType.DIRECT
    field_category: FieldCategory = FieldCategory.METADATA
    mapping_accuracy: MappingAccuracy = MappingAccuracy.EXACT
    confidence: float = 0.0
    transform_rule: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class MappingAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vendor_field: str = ""
    mapping_type: MappingType = MappingType.DIRECT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MappingReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    unmapped_count: int = 0
    avg_confidence: float = 0.0
    by_mapping_type: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_accuracy: dict[str, int] = Field(default_factory=dict)
    top_unmapped: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class VendorTelemetryMapperEngine:
    """Track and optimize vendor-to-OCSF field mapping accuracy."""

    def __init__(
        self,
        max_records: int = 200000,
        confidence_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._confidence_threshold = confidence_threshold
        self._records: list[MappingRecord] = []
        self._analyses: list[MappingAnalysis] = []
        logger.info(
            "vendor_telemetry_mapper_engine.initialized",
            max_records=max_records,
            confidence_threshold=confidence_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        vendor_field: str,
        ocsf_field: str,
        mapping_type: MappingType = MappingType.DIRECT,
        field_category: FieldCategory = FieldCategory.METADATA,
        mapping_accuracy: MappingAccuracy = MappingAccuracy.EXACT,
        confidence: float = 0.0,
        transform_rule: str = "",
        service: str = "",
        team: str = "",
    ) -> MappingRecord:
        record = MappingRecord(
            vendor_field=vendor_field,
            ocsf_field=ocsf_field,
            mapping_type=mapping_type,
            field_category=field_category,
            mapping_accuracy=mapping_accuracy,
            confidence=confidence,
            transform_rule=transform_rule,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "vendor_telemetry_mapper_engine.record_added",
            record_id=record.id,
            vendor_field=vendor_field,
            ocsf_field=ocsf_field,
        )
        return record

    def get_record(self, record_id: str) -> MappingRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        mapping_type: MappingType | None = None,
        field_category: FieldCategory | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[MappingRecord]:
        results = list(self._records)
        if mapping_type is not None:
            results = [r for r in results if r.mapping_type == mapping_type]
        if field_category is not None:
            results = [r for r in results if r.field_category == field_category]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        vendor_field: str,
        mapping_type: MappingType = MappingType.DIRECT,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> MappingAnalysis:
        analysis = MappingAnalysis(
            vendor_field=vendor_field,
            mapping_type=mapping_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "vendor_telemetry_mapper_engine.analysis_added",
            vendor_field=vendor_field,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_mapping_coverage(self) -> dict[str, Any]:
        """Group by field_category; return count and avg confidence."""
        cat_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.field_category.value
            cat_data.setdefault(key, []).append(r.confidence)
        result: dict[str, Any] = {}
        for cat, confs in cat_data.items():
            result[cat] = {
                "count": len(confs),
                "avg_confidence": round(sum(confs) / len(confs), 2),
            }
        return result

    def identify_unmapped_fields(self) -> list[dict[str, Any]]:
        """Return records where mapping_type is UNMAPPED or confidence < threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.mapping_type == MappingType.UNMAPPED or r.confidence < self._confidence_threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "vendor_field": r.vendor_field,
                        "ocsf_field": r.ocsf_field,
                        "mapping_type": r.mapping_type.value,
                        "confidence": r.confidence,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["confidence"])

    def detect_accuracy_trends(self) -> dict[str, Any]:
        """Split-half comparison on analysis_score; delta threshold 5.0."""
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [c.analysis_score for c in self._analyses]
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

    def generate_report(self) -> MappingReport:
        by_mapping_type: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_accuracy: dict[str, int] = {}
        for r in self._records:
            by_mapping_type[r.mapping_type.value] = by_mapping_type.get(r.mapping_type.value, 0) + 1
            by_category[r.field_category.value] = by_category.get(r.field_category.value, 0) + 1
            by_accuracy[r.mapping_accuracy.value] = by_accuracy.get(r.mapping_accuracy.value, 0) + 1
        unmapped_count = sum(1 for r in self._records if r.mapping_type == MappingType.UNMAPPED)
        confs = [r.confidence for r in self._records]
        avg_confidence = round(sum(confs) / len(confs), 2) if confs else 0.0
        unmapped_list = self.identify_unmapped_fields()
        top_unmapped = [o["vendor_field"] for o in unmapped_list[:5]]
        recs: list[str] = []
        if unmapped_count > 0:
            recs.append(f"{unmapped_count} field(s) remain unmapped to OCSF")
        if avg_confidence < self._confidence_threshold:
            recs.append(
                f"Avg mapping confidence {avg_confidence}% below threshold "
                f"({self._confidence_threshold}%)"
            )
        if not recs:
            recs.append("Vendor telemetry mapping accuracy is healthy")
        return MappingReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            unmapped_count=unmapped_count,
            avg_confidence=avg_confidence,
            by_mapping_type=by_mapping_type,
            by_category=by_category,
            by_accuracy=by_accuracy,
            top_unmapped=top_unmapped,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("vendor_telemetry_mapper_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            key = r.mapping_type.value
            type_dist[key] = type_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "confidence_threshold": self._confidence_threshold,
            "mapping_type_distribution": type_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
