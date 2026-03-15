"""Auto Instrumentation Coverage Engine —
compute instrumentation coverage, detect propagation breaks,
prioritize instrumentation gaps."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class InstrumentationLanguage(StrEnum):
    PYTHON = "python"
    JAVA = "java"
    NODE = "node"
    GO = "go"


class CoverageStatus(StrEnum):
    FULLY_INSTRUMENTED = "fully_instrumented"
    PARTIALLY_INSTRUMENTED = "partially_instrumented"
    UNINSTRUMENTED = "uninstrumented"
    MISCONFIGURED = "misconfigured"


class InstrumentationQuality(StrEnum):
    RICH_CONTEXT = "rich_context"
    BASIC_SPANS = "basic_spans"
    MISSING_ATTRIBUTES = "missing_attributes"
    BROKEN_PROPAGATION = "broken_propagation"


# --- Models ---


class AutoInstrumentationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_name: str = ""
    language: InstrumentationLanguage = InstrumentationLanguage.PYTHON
    coverage_status: CoverageStatus = CoverageStatus.FULLY_INSTRUMENTED
    instrumentation_quality: InstrumentationQuality = InstrumentationQuality.RICH_CONTEXT
    endpoint_count: int = 0
    instrumented_endpoints: int = 0
    propagation_breaks: int = 0
    missing_attribute_count: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AutoInstrumentationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_name: str = ""
    coverage_status: CoverageStatus = CoverageStatus.FULLY_INSTRUMENTED
    coverage_pct: float = 0.0
    propagation_broken: bool = False
    gap_priority_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AutoInstrumentationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_coverage_pct: float = 0.0
    by_language: dict[str, int] = Field(default_factory=dict)
    by_coverage_status: dict[str, int] = Field(default_factory=dict)
    by_instrumentation_quality: dict[str, int] = Field(default_factory=dict)
    uninstrumented_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AutoInstrumentationCoverageEngine:
    """Compute instrumentation coverage, detect propagation breaks,
    prioritize instrumentation gaps."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[AutoInstrumentationRecord] = []
        self._analyses: dict[str, AutoInstrumentationAnalysis] = {}
        logger.info("auto_instrumentation_coverage_engine.init", max_records=max_records)

    def add_record(
        self,
        service_name: str = "",
        language: InstrumentationLanguage = InstrumentationLanguage.PYTHON,
        coverage_status: CoverageStatus = CoverageStatus.FULLY_INSTRUMENTED,
        instrumentation_quality: InstrumentationQuality = InstrumentationQuality.RICH_CONTEXT,
        endpoint_count: int = 0,
        instrumented_endpoints: int = 0,
        propagation_breaks: int = 0,
        missing_attribute_count: int = 0,
        description: str = "",
    ) -> AutoInstrumentationRecord:
        record = AutoInstrumentationRecord(
            service_name=service_name,
            language=language,
            coverage_status=coverage_status,
            instrumentation_quality=instrumentation_quality,
            endpoint_count=endpoint_count,
            instrumented_endpoints=instrumented_endpoints,
            propagation_breaks=propagation_breaks,
            missing_attribute_count=missing_attribute_count,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "auto_instrumentation.record_added",
            record_id=record.id,
            service_name=service_name,
        )
        return record

    def process(self, key: str) -> AutoInstrumentationAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        coverage_pct = round(
            (rec.instrumented_endpoints / rec.endpoint_count * 100.0)
            if rec.endpoint_count > 0
            else 0.0,
            2,
        )
        propagation_broken = rec.propagation_breaks > 0 or (
            rec.instrumentation_quality == InstrumentationQuality.BROKEN_PROPAGATION
        )
        gap_priority = round(
            (100.0 - coverage_pct) * 0.6 + rec.propagation_breaks * 5.0,
            2,
        )
        analysis = AutoInstrumentationAnalysis(
            service_name=rec.service_name,
            coverage_status=rec.coverage_status,
            coverage_pct=coverage_pct,
            propagation_broken=propagation_broken,
            gap_priority_score=gap_priority,
            description=(f"Service {rec.service_name} coverage {coverage_pct:.1f}%"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> AutoInstrumentationReport:
        by_lang: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_quality: dict[str, int] = {}
        coverage_vals: list[float] = []
        uninstrumented: list[str] = []
        for r in self._records:
            kl = r.language.value
            by_lang[kl] = by_lang.get(kl, 0) + 1
            ks = r.coverage_status.value
            by_status[ks] = by_status.get(ks, 0) + 1
            kq = r.instrumentation_quality.value
            by_quality[kq] = by_quality.get(kq, 0) + 1
            pct = (
                (r.instrumented_endpoints / r.endpoint_count * 100.0)
                if r.endpoint_count > 0
                else 0.0
            )
            coverage_vals.append(pct)
            if (
                r.coverage_status == CoverageStatus.UNINSTRUMENTED
                and r.service_name not in uninstrumented
            ):
                uninstrumented.append(r.service_name)
        avg_cov = round(sum(coverage_vals) / len(coverage_vals), 2) if coverage_vals else 0.0
        recs: list[str] = []
        if uninstrumented:
            recs.append(f"{len(uninstrumented)} services are completely uninstrumented")
        broken_prop = by_quality.get("broken_propagation", 0)
        if broken_prop > 0:
            recs.append(f"{broken_prop} services have broken trace propagation")
        if not recs:
            recs.append("Instrumentation coverage is comprehensive")
        return AutoInstrumentationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_coverage_pct=avg_cov,
            by_language=by_lang,
            by_coverage_status=by_status,
            by_instrumentation_quality=by_quality,
            uninstrumented_services=uninstrumented[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        status_dist: dict[str, int] = {}
        for r in self._records:
            k = r.coverage_status.value
            status_dist[k] = status_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "coverage_status_distribution": status_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("auto_instrumentation_coverage_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def compute_instrumentation_coverage(self) -> list[dict[str, Any]]:
        """Compute per-service instrumentation coverage."""
        service_data: dict[str, list[AutoInstrumentationRecord]] = {}
        for r in self._records:
            service_data.setdefault(r.service_name, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, recs in service_data.items():
            total_endpoints = sum(r.endpoint_count for r in recs)
            total_instrumented = sum(r.instrumented_endpoints for r in recs)
            pct = round(
                (total_instrumented / total_endpoints * 100.0) if total_endpoints > 0 else 0.0,
                2,
            )
            results.append(
                {
                    "service_name": svc,
                    "coverage_pct": pct,
                    "total_endpoints": total_endpoints,
                    "instrumented_endpoints": total_instrumented,
                    "language": recs[-1].language.value,
                    "samples": len(recs),
                }
            )
        results.sort(key=lambda x: x["coverage_pct"])
        return results

    def detect_propagation_breaks(self) -> list[dict[str, Any]]:
        """Detect services with broken trace context propagation."""
        service_data: dict[str, list[AutoInstrumentationRecord]] = {}
        for r in self._records:
            service_data.setdefault(r.service_name, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, recs in service_data.items():
            total_breaks = sum(r.propagation_breaks for r in recs)
            broken_quality = sum(
                1
                for r in recs
                if r.instrumentation_quality == InstrumentationQuality.BROKEN_PROPAGATION
            )
            if total_breaks > 0 or broken_quality > 0:
                results.append(
                    {
                        "service_name": svc,
                        "total_propagation_breaks": total_breaks,
                        "broken_quality_samples": broken_quality,
                        "language": recs[-1].language.value,
                        "severity": "high" if total_breaks > 5 else "medium",
                    }
                )
        results.sort(key=lambda x: x["total_propagation_breaks"], reverse=True)
        return results

    def prioritize_instrumentation_gaps(self) -> list[dict[str, Any]]:
        """Rank services by instrumentation gap priority."""
        service_data: dict[str, list[AutoInstrumentationRecord]] = {}
        for r in self._records:
            service_data.setdefault(r.service_name, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, recs in service_data.items():
            total_endpoints = sum(r.endpoint_count for r in recs)
            total_instrumented = sum(r.instrumented_endpoints for r in recs)
            total_breaks = sum(r.propagation_breaks for r in recs)
            pct = (total_instrumented / total_endpoints * 100.0) if total_endpoints > 0 else 0.0
            priority_score = round((100.0 - pct) * 0.6 + total_breaks * 5.0, 2)
            if priority_score > 0:
                results.append(
                    {
                        "service_name": svc,
                        "coverage_pct": round(pct, 2),
                        "propagation_breaks": total_breaks,
                        "priority_score": priority_score,
                        "language": recs[-1].language.value,
                        "rank": 0,
                    }
                )
        results.sort(key=lambda x: x["priority_score"], reverse=True)
        for idx, entry in enumerate(results, 1):
            entry["rank"] = idx
        return results
