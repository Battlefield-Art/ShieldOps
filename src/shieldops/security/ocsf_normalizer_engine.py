"""OCSF Normalizer Engine — normalize vendor telemetry to OCSF schema."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class VendorFormat(StrEnum):
    CROWDSTRIKE = "crowdstrike"
    DEFENDER = "defender"
    SENTINELONE = "sentinelone"
    SPLUNK = "splunk"
    ELASTIC = "elastic"


class OCSFCategory(StrEnum):
    SECURITY_FINDING = "security_finding"
    DETECTION_FINDING = "detection_finding"
    VULNERABILITY_FINDING = "vulnerability_finding"


class NormalizationQuality(StrEnum):
    EXACT = "exact"
    APPROXIMATE = "approximate"
    PARTIAL = "partial"


# --- Models ---


class OCSFNormalizerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    vendor_format: VendorFormat = VendorFormat.CROWDSTRIKE
    ocsf_category: OCSFCategory = OCSFCategory.SECURITY_FINDING
    normalization_quality: NormalizationQuality = NormalizationQuality.EXACT
    score: float = 0.0
    field_count: int = 0
    mapped_fields: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class OCSFNormalizerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    vendor_format: VendorFormat = VendorFormat.CROWDSTRIKE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OCSFNormalizerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_vendor_format: dict[str, int] = Field(default_factory=dict)
    by_ocsf_category: dict[str, int] = Field(default_factory=dict)
    by_normalization_quality: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OCSFNormalizerEngine:
    """Normalize vendor telemetry to OCSF schema."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[OCSFNormalizerRecord] = []
        self._analyses: list[OCSFNormalizerAnalysis] = []
        logger.info(
            "ocsf_normalizer_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ---

    def add_record(
        self,
        name: str,
        vendor_format: VendorFormat = (VendorFormat.CROWDSTRIKE),
        ocsf_category: OCSFCategory = (OCSFCategory.SECURITY_FINDING),
        normalization_quality: (NormalizationQuality) = NormalizationQuality.EXACT,
        score: float = 0.0,
        field_count: int = 0,
        mapped_fields: int = 0,
        service: str = "",
        team: str = "",
    ) -> OCSFNormalizerRecord:
        record = OCSFNormalizerRecord(
            name=name,
            vendor_format=vendor_format,
            ocsf_category=ocsf_category,
            normalization_quality=(normalization_quality),
            score=score,
            field_count=field_count,
            mapped_fields=mapped_fields,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ocsf_normalizer_engine.record_added",
            record_id=record.id,
            name=name,
            vendor_format=vendor_format.value,
        )
        return record

    def get_record(self, record_id: str) -> OCSFNormalizerRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        vendor_format: VendorFormat | None = None,
        ocsf_category: OCSFCategory | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[OCSFNormalizerRecord]:
        results = list(self._records)
        if vendor_format is not None:
            results = [r for r in results if r.vendor_format == vendor_format]
        if ocsf_category is not None:
            results = [r for r in results if r.ocsf_category == ocsf_category]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        vendor_format: VendorFormat = (VendorFormat.CROWDSTRIKE),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> OCSFNormalizerAnalysis:
        analysis = OCSFNormalizerAnalysis(
            name=name,
            vendor_format=vendor_format,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "ocsf_normalizer_engine.analysis_added",
            name=name,
            vendor_format=vendor_format.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ---

    def normalize_event(
        self,
    ) -> list[dict[str, Any]]:
        """Normalize events and report mapping quality."""
        vendor_data: dict[str, list[OCSFNormalizerRecord]] = {}
        for r in self._records:
            vendor_data.setdefault(r.vendor_format.value, []).append(r)
        results: list[dict[str, Any]] = []
        for vendor, records in vendor_data.items():
            total_fields = sum(r.field_count for r in records)
            mapped = sum(r.mapped_fields for r in records)
            coverage = round(mapped / total_fields * 100, 1) if total_fields else 0.0
            quality_ct: dict[str, int] = {}
            for r in records:
                q = r.normalization_quality.value
                quality_ct[q] = quality_ct.get(q, 0) + 1
            results.append(
                {
                    "vendor": vendor,
                    "event_count": len(records),
                    "field_coverage_pct": coverage,
                    "total_fields": total_fields,
                    "mapped_fields": mapped,
                    "quality_distribution": quality_ct,
                }
            )
        return sorted(
            results,
            key=lambda x: x["field_coverage_pct"],
            reverse=True,
        )

    def validate_ocsf_compliance(
        self,
    ) -> list[dict[str, Any]]:
        """Validate OCSF compliance per vendor."""
        vendor_data: dict[str, list[OCSFNormalizerRecord]] = {}
        for r in self._records:
            vendor_data.setdefault(r.vendor_format.value, []).append(r)
        results: list[dict[str, Any]] = []
        for vendor, records in vendor_data.items():
            exact = sum(1 for r in records if r.normalization_quality == NormalizationQuality.EXACT)
            total = len(records)
            compliance = round(exact / total * 100, 1) if total else 0.0
            results.append(
                {
                    "vendor": vendor,
                    "total_events": total,
                    "exact_mappings": exact,
                    "compliance_pct": compliance,
                    "compliant": compliance >= 80.0,
                }
            )
        return sorted(
            results,
            key=lambda x: x["compliance_pct"],
        )

    def measure_coverage(
        self,
    ) -> dict[str, Any]:
        """Measure overall OCSF field coverage."""
        if not self._records:
            return {"coverage_pct": 0.0, "total": 0}
        total_f = sum(r.field_count for r in self._records)
        mapped_f = sum(r.mapped_fields for r in self._records)
        coverage = round(mapped_f / total_f * 100, 1) if total_f else 0.0
        by_category: dict[str, int] = {}
        for r in self._records:
            c = r.ocsf_category.value
            by_category[c] = by_category.get(c, 0) + 1
        return {
            "coverage_pct": coverage,
            "total_fields": total_f,
            "mapped_fields": mapped_f,
            "total_events": len(self._records),
            "by_category": by_category,
        }

    # -- standard methods ---

    def analyze_distribution(
        self,
    ) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.vendor_format.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "vendor_format": (r.vendor_format.value),
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc: dict[str, list[float]] = {}
        for r in self._records:
            svc.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for s, scores in svc.items():
            results.append(
                {
                    "service": s,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats ---

    def generate_report(
        self,
    ) -> OCSFNormalizerReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            k1 = r.vendor_format.value
            by_e1[k1] = by_e1.get(k1, 0) + 1
            k2 = r.ocsf_category.value
            by_e2[k2] = by_e2.get(k2, 0) + 1
            k3 = r.normalization_quality.value
            by_e3[k3] = by_e3.get(k3, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("OCSF Normalizer Engine is healthy")
        return OCSFNormalizerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_vendor_format=by_e1,
            by_ocsf_category=by_e2,
            by_normalization_quality=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("ocsf_normalizer_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.vendor_format.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "vendor_format_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
