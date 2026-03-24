"""AutoInstrumentationEngine — track auto-instrumentation coverage across services."""

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
    NODEJS = "nodejs"
    GO = "go"
    DOTNET = "dotnet"


class InstrumentationMethod(StrEnum):
    RUNTIME_PATCH = "runtime_patch"
    SDK_MANUAL = "sdk_manual"
    EBPF = "ebpf"
    OPERATOR_INJECTION = "operator_injection"


class CoverageStatus(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"
    INCOMPATIBLE = "incompatible"


# --- Models ---


class AutoInstrumentationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_name: str = ""
    language: InstrumentationLanguage = InstrumentationLanguage.PYTHON
    method: InstrumentationMethod = InstrumentationMethod.RUNTIME_PATCH
    coverage_status: CoverageStatus = CoverageStatus.NONE
    libraries_instrumented: int = 0
    libraries_total: int = 0
    trace_coverage_pct: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AutoInstrumentationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_name: str = ""
    coverage_pct: float = 0.0
    gap_count: int = 0
    method: InstrumentationMethod = InstrumentationMethod.RUNTIME_PATCH
    coverage_status: CoverageStatus = CoverageStatus.NONE
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AutoInstrumentationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_coverage_pct: float = 0.0
    by_language: dict[str, int] = Field(default_factory=dict)
    by_method: dict[str, int] = Field(default_factory=dict)
    by_coverage_status: dict[str, int] = Field(default_factory=dict)
    uninstrumented_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AutoInstrumentationEngine:
    """Track auto-instrumentation coverage — which services have OTel
    instrumentation, coverage gaps, library compatibility."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AutoInstrumentationRecord] = []
        self._analyses: list[AutoInstrumentationAnalysis] = []
        logger.info(
            "auto.instrumentation.engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        service_name: str,
        language: InstrumentationLanguage = InstrumentationLanguage.PYTHON,
        method: InstrumentationMethod = InstrumentationMethod.RUNTIME_PATCH,
        coverage_status: CoverageStatus = CoverageStatus.NONE,
        libraries_instrumented: int = 0,
        libraries_total: int = 0,
        trace_coverage_pct: float = 0.0,
        description: str = "",
    ) -> AutoInstrumentationRecord:
        record = AutoInstrumentationRecord(
            service_name=service_name,
            language=language,
            method=method,
            coverage_status=coverage_status,
            libraries_instrumented=libraries_instrumented,
            libraries_total=libraries_total,
            trace_coverage_pct=trace_coverage_pct,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "auto.instrumentation.engine.record_added",
            record_id=record.id,
            service_name=service_name,
            language=language.value,
            method=method.value,
        )
        return record

    def get_record(self, record_id: str) -> AutoInstrumentationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        language: InstrumentationLanguage | None = None,
        method: InstrumentationMethod | None = None,
        service_name: str | None = None,
        limit: int = 50,
    ) -> list[AutoInstrumentationRecord]:
        results = list(self._records)
        if language is not None:
            results = [r for r in results if r.language == language]
        if method is not None:
            results = [r for r in results if r.method == method]
        if service_name is not None:
            results = [r for r in results if r.service_name == service_name]
        return results[-limit:]

    # -- process ------------------------------------------------------------

    def process(self, key: str) -> AutoInstrumentationAnalysis | None:
        matched = [r for r in self._records if r.service_name == key]
        if not matched:
            return None
        coverage_vals = [r.trace_coverage_pct for r in matched]
        avg_coverage = round(sum(coverage_vals) / len(coverage_vals), 2)
        gap_count = sum(
            1 for r in matched if r.coverage_status in (CoverageStatus.NONE, CoverageStatus.PARTIAL)
        )
        latest = matched[-1]
        if avg_coverage >= 90.0:
            status = CoverageStatus.FULL
        elif avg_coverage >= 50.0:
            status = CoverageStatus.PARTIAL
        else:
            status = CoverageStatus.NONE
        analysis = AutoInstrumentationAnalysis(
            service_name=key,
            coverage_pct=avg_coverage,
            gap_count=gap_count,
            method=latest.method,
            coverage_status=status,
            description=f"Analyzed {len(matched)} records for service {key}",
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "auto.instrumentation.engine.processed",
            service_name=key,
            coverage_pct=avg_coverage,
            gap_count=gap_count,
            coverage_status=status.value,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_coverage_gaps(self) -> list[dict[str, Any]]:
        """Find services with NONE or PARTIAL coverage."""
        results: list[dict[str, Any]] = []
        service_data: dict[str, list[AutoInstrumentationRecord]] = {}
        for r in self._records:
            service_data.setdefault(r.service_name, []).append(r)
        for svc, records in service_data.items():
            gaps = [
                r
                for r in records
                if r.coverage_status in (CoverageStatus.NONE, CoverageStatus.PARTIAL)
            ]
            if gaps:
                avg_coverage = round(sum(r.trace_coverage_pct for r in records) / len(records), 2)
                results.append(
                    {
                        "service_name": svc,
                        "gap_count": len(gaps),
                        "avg_coverage_pct": avg_coverage,
                        "language": records[-1].language.value,
                    }
                )
        return sorted(results, key=lambda x: x["avg_coverage_pct"])

    def recommend_instrumentation_method(self) -> list[dict[str, Any]]:
        """Suggest best instrumentation method per language."""
        language_methods: dict[str, dict[str, list[float]]] = {}
        for r in self._records:
            lang = r.language.value
            method = r.method.value
            language_methods.setdefault(lang, {}).setdefault(method, []).append(
                r.trace_coverage_pct
            )
        results: list[dict[str, Any]] = []
        for lang, methods in language_methods.items():
            best_method = ""
            best_avg = -1.0
            for method, coverages in methods.items():
                avg = sum(coverages) / len(coverages)
                if avg > best_avg:
                    best_avg = avg
                    best_method = method
            results.append(
                {
                    "language": lang,
                    "recommended_method": best_method,
                    "avg_coverage_pct": round(best_avg, 2),
                    "methods_evaluated": len(methods),
                }
            )
        return results

    def calculate_overall_coverage(self) -> dict[str, Any]:
        """Compute weighted coverage across all services."""
        if not self._records:
            return {
                "overall_coverage_pct": 0.0,
                "total_services": 0,
                "fully_covered": 0,
                "partially_covered": 0,
                "not_covered": 0,
            }
        service_coverage: dict[str, list[float]] = {}
        service_status: dict[str, list[CoverageStatus]] = {}
        for r in self._records:
            service_coverage.setdefault(r.service_name, []).append(r.trace_coverage_pct)
            service_status.setdefault(r.service_name, []).append(r.coverage_status)
        total_services = len(service_coverage)
        avg_per_service = []
        fully = 0
        partial = 0
        none_count = 0
        for _svc, coverages in service_coverage.items():
            avg = sum(coverages) / len(coverages)
            avg_per_service.append(avg)
            if avg >= 90.0:
                fully += 1
            elif avg >= 50.0:
                partial += 1
            else:
                none_count += 1
        overall = round(sum(avg_per_service) / len(avg_per_service), 2)
        return {
            "overall_coverage_pct": overall,
            "total_services": total_services,
            "fully_covered": fully,
            "partially_covered": partial,
            "not_covered": none_count,
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> AutoInstrumentationReport:
        by_lang: dict[str, int] = {}
        by_method: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for r in self._records:
            by_lang[r.language.value] = by_lang.get(r.language.value, 0) + 1
            by_method[r.method.value] = by_method.get(r.method.value, 0) + 1
            by_status[r.coverage_status.value] = by_status.get(r.coverage_status.value, 0) + 1
        coverages = [r.trace_coverage_pct for r in self._records]
        avg_coverage = round(sum(coverages) / len(coverages), 2) if coverages else 0.0
        uninstrumented = list(
            {r.service_name for r in self._records if r.coverage_status == CoverageStatus.NONE}
        )
        recs: list[str] = []
        if uninstrumented:
            recs.append(f"{len(uninstrumented)} service(s) have no instrumentation")
        if avg_coverage < self._threshold and self._records:
            recs.append(f"Avg coverage {avg_coverage}% below threshold ({self._threshold}%)")
        if not recs:
            recs.append("Auto Instrumentation Engine is healthy")
        return AutoInstrumentationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_coverage_pct=avg_coverage,
            by_language=by_lang,
            by_method=by_method,
            by_coverage_status=by_status,
            uninstrumented_services=uninstrumented,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("auto.instrumentation.engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        lang_dist: dict[str, int] = {}
        for r in self._records:
            key = r.language.value
            lang_dist[key] = lang_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "language_distribution": lang_dist,
            "unique_services": len({r.service_name for r in self._records}),
        }
