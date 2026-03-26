"""OCSF Event Mapper — map vendor events to OCSF schema."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class VendorSchema(StrEnum):
    CROWDSTRIKE = "crowdstrike"
    DEFENDER = "defender"
    WIZ = "wiz"
    SPLUNK = "splunk"
    ELASTIC = "elastic"


class OCSFCategory(StrEnum):
    SECURITY_FINDING = "security_finding"
    DETECTION_FINDING = "detection_finding"
    VULNERABILITY = "vulnerability"


class MappingQuality(StrEnum):
    EXACT = "exact"
    APPROXIMATE = "approximate"
    PARTIAL = "partial"


# --- Models ---


class OCSFMappingRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vendor: VendorSchema = VendorSchema.CROWDSTRIKE
    ocsf_category: OCSFCategory = OCSFCategory.SECURITY_FINDING
    quality: MappingQuality = MappingQuality.EXACT
    vendor_event_type: str = ""
    ocsf_class_uid: int = 0
    ocsf_activity_id: int = 0
    fields_mapped: int = 0
    fields_total: int = 0
    unmapped_fields: list[str] = Field(default_factory=list)
    validated: bool = False
    created_at: float = Field(default_factory=time.time)


class OCSFMappingAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vendor: str = ""
    total_mappings: int = 0
    exact_count: int = 0
    approximate_count: int = 0
    partial_count: int = 0
    avg_coverage: float = 0.0
    validated_rate: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class OCSFMappingReport(BaseModel):
    total_mappings: int = 0
    by_vendor: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_quality: dict[str, int] = Field(default_factory=dict)
    avg_field_coverage_pct: float = 0.0
    validated_rate_pct: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class OCSFEventMapperEngine:
    """Map vendor security events to OCSF schema."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[OCSFMappingRecord] = []
        logger.info(
            "ocsf_event_mapper.initialized",
            max_records=max_records,
        )

    # -- record / query --

    def add_record(
        self,
        vendor: VendorSchema = (VendorSchema.CROWDSTRIKE),
        ocsf_category: OCSFCategory = (OCSFCategory.SECURITY_FINDING),
        vendor_event_type: str = "",
        ocsf_class_uid: int = 0,
        ocsf_activity_id: int = 0,
        fields_mapped: int = 0,
        fields_total: int = 0,
        unmapped_fields: list[str] | None = None,
    ) -> OCSFMappingRecord:
        if fields_total > 0:
            ratio = fields_mapped / fields_total
            if ratio >= 0.95:
                quality = MappingQuality.EXACT
            elif ratio >= 0.7:
                quality = MappingQuality.APPROXIMATE
            else:
                quality = MappingQuality.PARTIAL
        else:
            quality = MappingQuality.PARTIAL
        record = OCSFMappingRecord(
            vendor=vendor,
            ocsf_category=ocsf_category,
            quality=quality,
            vendor_event_type=vendor_event_type,
            ocsf_class_uid=ocsf_class_uid,
            ocsf_activity_id=ocsf_activity_id,
            fields_mapped=fields_mapped,
            fields_total=fields_total,
            unmapped_fields=unmapped_fields or [],
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ocsf_event_mapper.record_added",
            record_id=record.id,
            vendor=vendor.value,
            quality=quality.value,
        )
        return record

    def process(self, vendor: str) -> OCSFMappingAnalysis:
        items = [r for r in self._records if r.vendor.value == vendor]
        if not items:
            return OCSFMappingAnalysis(vendor=vendor)
        exact = sum(1 for r in items if r.quality == MappingQuality.EXACT)
        approx = sum(1 for r in items if r.quality == MappingQuality.APPROXIMATE)
        partial = sum(1 for r in items if r.quality == MappingQuality.PARTIAL)
        coverages = [r.fields_mapped / r.fields_total for r in items if r.fields_total > 0]
        avg_cov = (
            round(
                sum(coverages) / len(coverages) * 100,
                2,
            )
            if coverages
            else 0.0
        )
        validated = sum(1 for r in items if r.validated)
        val_rate = round(validated / len(items) * 100, 2)
        return OCSFMappingAnalysis(
            vendor=vendor,
            total_mappings=len(items),
            exact_count=exact,
            approximate_count=approx,
            partial_count=partial,
            avg_coverage=avg_cov,
            validated_rate=val_rate,
        )

    def generate_report(self) -> OCSFMappingReport:
        by_vendor: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_quality: dict[str, int] = {}
        for r in self._records:
            by_vendor[r.vendor.value] = by_vendor.get(r.vendor.value, 0) + 1
            by_category[r.ocsf_category.value] = by_category.get(r.ocsf_category.value, 0) + 1
            by_quality[r.quality.value] = by_quality.get(r.quality.value, 0) + 1
        total = len(self._records)
        coverages = [r.fields_mapped / r.fields_total for r in self._records if r.fields_total > 0]
        avg_cov = (
            round(
                sum(coverages) / len(coverages) * 100,
                2,
            )
            if coverages
            else 0.0
        )
        validated = sum(1 for r in self._records if r.validated)
        val_rate = round(validated / total * 100, 2) if total else 0.0
        recs: list[str] = []
        partial_ct = by_quality.get(MappingQuality.PARTIAL.value, 0)
        if partial_ct > 0:
            recs.append(f"{partial_ct} partial mapping(s) need improvement")
        if avg_cov < 80 and total > 0:
            recs.append("Field coverage below 80% — review unmapped fields")
        if val_rate < 50 and total > 0:
            recs.append("Low validation rate — run OCSF schema validation")
        if not recs:
            recs.append("OCSF mapping quality is good")
        return OCSFMappingReport(
            total_mappings=total,
            by_vendor=by_vendor,
            by_category=by_category,
            by_quality=by_quality,
            avg_field_coverage_pct=avg_cov,
            validated_rate_pct=val_rate,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        vendor_dist: dict[str, int] = {}
        for r in self._records:
            key = r.vendor.value
            vendor_dist[key] = vendor_dist.get(key, 0) + 1
        return {
            "total_mappings": len(self._records),
            "max_records": self._max_records,
            "vendor_distribution": vendor_dist,
            "validated": sum(1 for r in self._records if r.validated),
            "unique_event_types": len({r.vendor_event_type for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("ocsf_event_mapper.cleared")
        return {"status": "cleared"}

    # -- domain operations --

    def map_vendor_event(
        self,
        vendor: VendorSchema,
        vendor_event_type: str,
        ocsf_category: OCSFCategory = (OCSFCategory.SECURITY_FINDING),
        ocsf_class_uid: int = 0,
        ocsf_activity_id: int = 0,
        fields_mapped: int = 0,
        fields_total: int = 0,
        unmapped_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Map a vendor event to OCSF schema."""
        record = self.add_record(
            vendor=vendor,
            ocsf_category=ocsf_category,
            vendor_event_type=vendor_event_type,
            ocsf_class_uid=ocsf_class_uid,
            ocsf_activity_id=ocsf_activity_id,
            fields_mapped=fields_mapped,
            fields_total=fields_total,
            unmapped_fields=unmapped_fields,
        )
        return {
            "record_id": record.id,
            "vendor": vendor.value,
            "event_type": vendor_event_type,
            "ocsf_category": ocsf_category.value,
            "quality": record.quality.value,
            "field_coverage": (
                round(
                    fields_mapped / fields_total * 100,
                    2,
                )
                if fields_total > 0
                else 0.0
            ),
        }

    def validate_ocsf(
        self,
        record_id: str,
    ) -> dict[str, Any]:
        """Validate a mapping against OCSF spec."""
        record = None
        for r in self._records:
            if r.id == record_id:
                record = r
                break
        if record is None:
            return {
                "found": False,
                "record_id": record_id,
            }
        is_valid = record.quality != MappingQuality.PARTIAL and record.ocsf_class_uid > 0
        record.validated = is_valid
        logger.info(
            "ocsf_event_mapper.validated",
            record_id=record_id,
            valid=is_valid,
        )
        return {
            "found": True,
            "record_id": record_id,
            "valid": is_valid,
            "quality": record.quality.value,
            "class_uid": record.ocsf_class_uid,
            "unmapped_fields": record.unmapped_fields,
        }

    def measure_coverage(
        self,
        vendor: VendorSchema | None = None,
    ) -> dict[str, Any]:
        """Measure OCSF mapping coverage."""
        targets = self._records
        if vendor:
            targets = [r for r in self._records if r.vendor == vendor]
        if not targets:
            return {
                "vendor": (vendor.value if vendor else "all"),
                "total": 0,
                "coverage_pct": 0.0,
            }
        coverages = [r.fields_mapped / r.fields_total for r in targets if r.fields_total > 0]
        avg = (
            round(
                sum(coverages) / len(coverages) * 100,
                2,
            )
            if coverages
            else 0.0
        )
        quality_dist: dict[str, int] = {}
        for r in targets:
            key = r.quality.value
            quality_dist[key] = quality_dist.get(key, 0) + 1
        return {
            "vendor": (vendor.value if vendor else "all"),
            "total": len(targets),
            "coverage_pct": avg,
            "quality_distribution": quality_dist,
            "validated": sum(1 for r in targets if r.validated),
        }
