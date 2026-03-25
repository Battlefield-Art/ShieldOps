"""OCSF Schema Normalizer Engine — track and optimize OCSF schema normalization quality."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class VendorSource(StrEnum):
    CROWDSTRIKE = "crowdstrike"
    MICROSOFT_DEFENDER = "microsoft_defender"
    WIZ = "wiz"
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    DATADOG = "datadog"
    NEWRELIC = "newrelic"
    PAGERDUTY = "pagerduty"
    SERVICENOW = "servicenow"
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class OCSFCategory(StrEnum):
    SECURITY_FINDING = "security_finding"
    DETECTION_FINDING = "detection_finding"
    VULNERABILITY_FINDING = "vulnerability_finding"
    IDENTITY_ACTIVITY = "identity_activity"
    NETWORK_ACTIVITY = "network_activity"
    SYSTEM_ACTIVITY = "system_activity"


class NormalizationQuality(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    MODERATE = "moderate"
    POOR = "poor"
    FAILED = "failed"


# --- Models ---


class NormalizationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vendor_source: VendorSource = VendorSource.SPLUNK
    ocsf_category: OCSFCategory = OCSFCategory.SECURITY_FINDING
    normalization_quality: NormalizationQuality = NormalizationQuality.EXCELLENT
    completeness_score: float = 0.0
    field_mapping_count: int = 0
    unmapped_fields: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class NormalizationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vendor_source: VendorSource = VendorSource.SPLUNK
    ocsf_category: OCSFCategory = OCSFCategory.SECURITY_FINDING
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class NormalizationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    poor_quality_count: int = 0
    avg_completeness: float = 0.0
    by_vendor: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_quality: dict[str, int] = Field(default_factory=dict)
    top_unmapped: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OCSFSchemaNormalizerEngine:
    """Track and optimize OCSF schema normalization quality."""

    def __init__(
        self,
        max_records: int = 200000,
        completeness_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._completeness_threshold = completeness_threshold
        self._records: list[NormalizationRecord] = []
        self._analyses: list[NormalizationAnalysis] = []
        logger.info(
            "ocsf_schema_normalizer_engine.initialized",
            max_records=max_records,
            completeness_threshold=completeness_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        vendor_source: VendorSource = VendorSource.SPLUNK,
        ocsf_category: OCSFCategory = OCSFCategory.SECURITY_FINDING,
        normalization_quality: NormalizationQuality = NormalizationQuality.EXCELLENT,
        completeness_score: float = 0.0,
        field_mapping_count: int = 0,
        unmapped_fields: int = 0,
        service: str = "",
        team: str = "",
    ) -> NormalizationRecord:
        record = NormalizationRecord(
            vendor_source=vendor_source,
            ocsf_category=ocsf_category,
            normalization_quality=normalization_quality,
            completeness_score=completeness_score,
            field_mapping_count=field_mapping_count,
            unmapped_fields=unmapped_fields,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ocsf_schema_normalizer_engine.record_added",
            record_id=record.id,
            vendor_source=vendor_source.value,
            ocsf_category=ocsf_category.value,
        )
        return record

    def get_record(self, record_id: str) -> NormalizationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        vendor_source: VendorSource | None = None,
        ocsf_category: OCSFCategory | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[NormalizationRecord]:
        results = list(self._records)
        if vendor_source is not None:
            results = [r for r in results if r.vendor_source == vendor_source]
        if ocsf_category is not None:
            results = [r for r in results if r.ocsf_category == ocsf_category]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        vendor_source: VendorSource = VendorSource.SPLUNK,
        ocsf_category: OCSFCategory = OCSFCategory.SECURITY_FINDING,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> NormalizationAnalysis:
        analysis = NormalizationAnalysis(
            vendor_source=vendor_source,
            ocsf_category=ocsf_category,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "ocsf_schema_normalizer_engine.analysis_added",
            vendor_source=vendor_source.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_vendor_coverage(self) -> dict[str, Any]:
        """Group by vendor_source; return count and avg completeness_score."""
        vendor_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.vendor_source.value
            vendor_data.setdefault(key, []).append(r.completeness_score)
        result: dict[str, Any] = {}
        for vendor, scores in vendor_data.items():
            result[vendor] = {
                "count": len(scores),
                "avg_completeness": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_poor_normalizations(self) -> list[dict[str, Any]]:
        """Return records where completeness_score < completeness_threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.completeness_score < self._completeness_threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "vendor_source": r.vendor_source.value,
                        "ocsf_category": r.ocsf_category.value,
                        "completeness_score": r.completeness_score,
                        "unmapped_fields": r.unmapped_fields,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["completeness_score"])

    def detect_quality_trends(self) -> dict[str, Any]:
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

    def generate_report(self) -> NormalizationReport:
        by_vendor: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_quality: dict[str, int] = {}
        for r in self._records:
            by_vendor[r.vendor_source.value] = by_vendor.get(r.vendor_source.value, 0) + 1
            by_category[r.ocsf_category.value] = by_category.get(r.ocsf_category.value, 0) + 1
            by_quality[r.normalization_quality.value] = (
                by_quality.get(r.normalization_quality.value, 0) + 1
            )
        poor_quality_count = sum(
            1 for r in self._records if r.completeness_score < self._completeness_threshold
        )
        scores = [r.completeness_score for r in self._records]
        avg_completeness = round(sum(scores) / len(scores), 2) if scores else 0.0
        poor_list = self.identify_poor_normalizations()
        top_unmapped = [o["vendor_source"] for o in poor_list[:5]]
        recs: list[str] = []
        if poor_quality_count > 0:
            recs.append(
                f"{poor_quality_count} normalization(s) below completeness threshold "
                f"({self._completeness_threshold}%)"
            )
        if avg_completeness < self._completeness_threshold:
            recs.append(
                f"Avg completeness {avg_completeness}% below threshold "
                f"({self._completeness_threshold}%)"
            )
        if not recs:
            recs.append("OCSF schema normalization quality is healthy")
        return NormalizationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            poor_quality_count=poor_quality_count,
            avg_completeness=avg_completeness,
            by_vendor=by_vendor,
            by_category=by_category,
            by_quality=by_quality,
            top_unmapped=top_unmapped,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("ocsf_schema_normalizer_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        vendor_dist: dict[str, int] = {}
        for r in self._records:
            key = r.vendor_source.value
            vendor_dist[key] = vendor_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "completeness_threshold": self._completeness_threshold,
            "vendor_distribution": vendor_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
