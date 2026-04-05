"""Baseline Compliance Engine — track config baseline compliance rates."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BaselineSource(StrEnum):
    GOLDEN_IMAGE = "golden_image"
    POLICY_FILE = "policy_file"
    CIS_BENCHMARK = "cis_benchmark"
    CUSTOM_RULE = "custom_rule"
    INHERITED = "inherited"


class ComplianceLevel(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    EXEMPT = "exempt"
    UNKNOWN = "unknown"


class ValidationTrigger(StrEnum):
    SCHEDULED = "scheduled"
    ON_CHANGE = "on_change"
    ON_DEPLOY = "on_deploy"
    MANUAL = "manual"
    CONTINUOUS = "continuous"


# --- Models ---


class BaselineComplianceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource_id: str = ""
    service_id: str = ""
    baseline_source: BaselineSource = BaselineSource.POLICY_FILE
    compliance_level: ComplianceLevel = ComplianceLevel.UNKNOWN
    validation_trigger: ValidationTrigger = ValidationTrigger.SCHEDULED
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    compliance_pct: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class BaselineComplianceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource_id: str = ""
    analysis_score: float = 0.0
    baseline_source: BaselineSource = BaselineSource.POLICY_FILE
    trend: str = ""
    data_points: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class BaselineComplianceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_compliance_pct: float = 0.0
    by_source: dict[str, int] = Field(default_factory=dict)
    by_level: dict[str, int] = Field(default_factory=dict)
    by_trigger: dict[str, int] = Field(default_factory=dict)
    non_compliant_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class BaselineComplianceEngine:
    """Track config baseline compliance rates across infrastructure."""

    def __init__(
        self,
        max_records: int = 200000,
        compliance_threshold: float = 95.0,
    ) -> None:
        self._max_records = max_records
        self._compliance_threshold = compliance_threshold
        self._records: list[BaselineComplianceRecord] = []
        self._analyses: dict[str, BaselineComplianceAnalysis] = {}
        logger.info(
            "baseline_compliance_engine.init",
            max_records=max_records,
            compliance_threshold=compliance_threshold,
        )

    def add_record(
        self,
        resource_id: str = "",
        service_id: str = "",
        baseline_source: BaselineSource = BaselineSource.POLICY_FILE,
        compliance_level: ComplianceLevel = ComplianceLevel.UNKNOWN,
        validation_trigger: ValidationTrigger = ValidationTrigger.SCHEDULED,
        total_checks: int = 0,
        passed_checks: int = 0,
        failed_checks: int = 0,
        compliance_pct: float = 0.0,
        description: str = "",
    ) -> BaselineComplianceRecord:
        record = BaselineComplianceRecord(
            resource_id=resource_id,
            service_id=service_id,
            baseline_source=baseline_source,
            compliance_level=compliance_level,
            validation_trigger=validation_trigger,
            total_checks=total_checks,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            compliance_pct=compliance_pct,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "baseline_compliance_engine.record_added",
            record_id=record.id,
            resource_id=resource_id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> BaselineComplianceAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        res_recs = [r for r in self._records if r.resource_id == rec.resource_id]
        pcts = [r.compliance_pct for r in res_recs]
        avg = round(sum(pcts) / len(pcts), 2) if pcts else 0.0
        # Determine trend
        trend = "stable"
        if len(pcts) >= 4:
            mid = len(pcts) // 2
            first = sum(pcts[:mid]) / mid
            second = sum(pcts[mid:]) / len(pcts[mid:])
            delta = second - first
            if delta > 5:
                trend = "improving"
            elif delta < -5:
                trend = "degrading"
        analysis = BaselineComplianceAnalysis(
            resource_id=rec.resource_id,
            analysis_score=avg,
            baseline_source=rec.baseline_source,
            trend=trend,
            data_points=len(res_recs),
            description=(f"Compliance {avg}% for {rec.resource_id} — {trend}"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> BaselineComplianceReport:
        by_s: dict[str, int] = {}
        by_l: dict[str, int] = {}
        by_t: dict[str, int] = {}
        pcts: list[float] = []
        for r in self._records:
            by_s[r.baseline_source.value] = by_s.get(r.baseline_source.value, 0) + 1
            by_l[r.compliance_level.value] = by_l.get(r.compliance_level.value, 0) + 1
            by_t[r.validation_trigger.value] = by_t.get(r.validation_trigger.value, 0) + 1
            pcts.append(r.compliance_pct)
        avg = round(sum(pcts) / len(pcts), 2) if pcts else 0.0
        non_compliant = list(
            {
                r.service_id
                for r in self._records
                if r.compliance_level == ComplianceLevel.NON_COMPLIANT
            }
        )[:10]
        recs: list[str] = []
        if avg < self._compliance_threshold:
            recs.append(f"Average compliance {avg}% below threshold {self._compliance_threshold}%")
        if non_compliant:
            recs.append(f"{len(non_compliant)} services non-compliant with baseline")
        failed_total = sum(r.failed_checks for r in self._records)
        if failed_total:
            recs.append(f"{failed_total} total failed checks across fleet")
        if not recs:
            recs.append("Baseline compliance healthy across all resources")
        return BaselineComplianceReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_compliance_pct=avg,
            by_source=by_s,
            by_level=by_l,
            by_trigger=by_t,
            non_compliant_services=non_compliant,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        source_dist: dict[str, int] = {}
        for r in self._records:
            k = r.baseline_source.value
            source_dist[k] = source_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "compliance_threshold": self._compliance_threshold,
            "source_distribution": source_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("baseline_compliance_engine.cleared")
        return {"status": "cleared"}

    # -- domain methods ---

    def rank_services_by_compliance(self) -> list[dict[str, Any]]:
        """Rank services by average compliance percentage."""
        svc_pcts: dict[str, list[float]] = {}
        for r in self._records:
            svc_pcts.setdefault(r.service_id, []).append(r.compliance_pct)
        results: list[dict[str, Any]] = []
        for sid, pcts in svc_pcts.items():
            avg = round(sum(pcts) / len(pcts), 2)
            results.append(
                {
                    "service_id": sid,
                    "avg_compliance_pct": avg,
                    "check_count": len(pcts),
                }
            )
        results.sort(key=lambda x: x["avg_compliance_pct"])
        return results

    def identify_common_failures(self) -> list[dict[str, Any]]:
        """Identify most common baseline check failures."""
        source_failures: dict[str, int] = {}
        source_total: dict[str, int] = {}
        for r in self._records:
            k = r.baseline_source.value
            source_failures[k] = source_failures.get(k, 0) + r.failed_checks
            source_total[k] = source_total.get(k, 0) + r.total_checks
        results: list[dict[str, Any]] = []
        for source, fails in source_failures.items():
            total = source_total.get(source, 0)
            rate = round(fails / total * 100, 2) if total > 0 else 0.0
            results.append(
                {
                    "baseline_source": source,
                    "failed_checks": fails,
                    "total_checks": total,
                    "failure_rate_pct": rate,
                }
            )
        results.sort(key=lambda x: x["failure_rate_pct"], reverse=True)
        return results

    def summarize_validation_coverage(self) -> list[dict[str, Any]]:
        """Summarize validation trigger coverage."""
        trigger_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            k = r.validation_trigger.value
            trigger_data.setdefault(k, {"total": 0, "compliant": 0})
            trigger_data[k]["total"] += 1
            if r.compliance_level == ComplianceLevel.FULL:
                trigger_data[k]["compliant"] += 1
        results: list[dict[str, Any]] = []
        for trigger, data in trigger_data.items():
            rate = round(data["compliant"] / data["total"] * 100, 2) if data["total"] else 0.0
            results.append(
                {
                    "validation_trigger": trigger,
                    "total_validations": data["total"],
                    "compliant_count": data["compliant"],
                    "compliance_rate_pct": rate,
                }
            )
        results.sort(key=lambda x: x["total_validations"], reverse=True)
        return results
