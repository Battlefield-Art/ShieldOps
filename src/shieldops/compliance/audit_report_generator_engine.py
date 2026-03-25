"""Audit Report Generator Engine — track and analyze compliance audit report generation."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ReportType(StrEnum):
    SOC2_TYPE2 = "soc2_type2"
    PCI_ROC = "pci_roc"
    HIPAA_ASSESSMENT = "hipaa_assessment"
    FEDRAMP_PACKAGE = "fedramp_package"
    GDPR_DPIA = "gdpr_dpia"


class ReportStatus(StrEnum):
    DRAFT = "draft"
    REVIEW = "review"
    APPROVED = "approved"
    DELIVERED = "delivered"
    ARCHIVED = "archived"


class AuditOutcome(StrEnum):
    CLEAN = "clean"
    QUALIFIED = "qualified"
    ADVERSE = "adverse"
    DISCLAIMER = "disclaimer"


# --- Models ---


class AuditReportRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    report_name: str = ""
    report_type: ReportType = ReportType.SOC2_TYPE2
    report_status: ReportStatus = ReportStatus.DRAFT
    audit_outcome: AuditOutcome = AuditOutcome.CLEAN
    total_controls: int = 0
    compliant_controls: int = 0
    compliance_score: float = 0.0
    generation_time_ms: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AuditReportAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    report_name: str = ""
    report_type: ReportType = ReportType.SOC2_TYPE2
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AuditReportReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    non_compliant_count: int = 0
    avg_compliance_score: float = 0.0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    top_issues: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AuditReportGeneratorEngine:
    """Track and analyze compliance audit report generation."""

    def __init__(
        self,
        max_records: int = 200000,
        compliance_threshold: float = 90.0,
    ) -> None:
        self._max_records = max_records
        self._compliance_threshold = compliance_threshold
        self._records: list[AuditReportRecord] = []
        self._analyses: list[AuditReportAnalysis] = []
        logger.info(
            "audit_report_generator_engine.initialized",
            max_records=max_records,
            compliance_threshold=compliance_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        report_name: str,
        report_type: ReportType = ReportType.SOC2_TYPE2,
        report_status: ReportStatus = ReportStatus.DRAFT,
        audit_outcome: AuditOutcome = AuditOutcome.CLEAN,
        total_controls: int = 0,
        compliant_controls: int = 0,
        compliance_score: float = 0.0,
        generation_time_ms: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> AuditReportRecord:
        record = AuditReportRecord(
            report_name=report_name,
            report_type=report_type,
            report_status=report_status,
            audit_outcome=audit_outcome,
            total_controls=total_controls,
            compliant_controls=compliant_controls,
            compliance_score=compliance_score,
            generation_time_ms=generation_time_ms,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "audit_report_generator_engine.record_added",
            record_id=record.id,
            report_name=report_name,
            report_type=report_type.value,
        )
        return record

    def get_record(self, record_id: str) -> AuditReportRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        report_type: ReportType | None = None,
        report_status: ReportStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AuditReportRecord]:
        results = list(self._records)
        if report_type is not None:
            results = [r for r in results if r.report_type == report_type]
        if report_status is not None:
            results = [r for r in results if r.report_status == report_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        report_name: str,
        report_type: ReportType = ReportType.SOC2_TYPE2,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AuditReportAnalysis:
        analysis = AuditReportAnalysis(
            report_name=report_name,
            report_type=report_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "audit_report_generator_engine.analysis_added",
            report_name=report_name,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_compliance_trends(self) -> dict[str, Any]:
        """Group by report_type; return count and avg compliance_score."""
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.report_type.value
            type_data.setdefault(key, []).append(r.compliance_score)
        result: dict[str, Any] = {}
        for rtype, scores in type_data.items():
            result[rtype] = {
                "count": len(scores),
                "avg_compliance_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_non_compliant_areas(self) -> list[dict[str, Any]]:
        """Return records where compliance_score < compliance_threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.compliance_score < self._compliance_threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "report_name": r.report_name,
                        "report_type": r.report_type.value,
                        "compliance_score": r.compliance_score,
                        "audit_outcome": r.audit_outcome.value,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["compliance_score"])

    def detect_report_quality_trends(self) -> dict[str, Any]:
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

    def generate_report(self) -> AuditReportReport:
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        for r in self._records:
            by_type[r.report_type.value] = by_type.get(r.report_type.value, 0) + 1
            by_status[r.report_status.value] = by_status.get(r.report_status.value, 0) + 1
            by_outcome[r.audit_outcome.value] = by_outcome.get(r.audit_outcome.value, 0) + 1
        non_compliant_count = sum(
            1 for r in self._records if r.compliance_score < self._compliance_threshold
        )
        scores = [r.compliance_score for r in self._records]
        avg_compliance_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        nc_list = self.identify_non_compliant_areas()
        top_issues = [n["report_name"] for n in nc_list[:5]]
        recs: list[str] = []
        if non_compliant_count > 0:
            recs.append(
                f"{non_compliant_count} report(s) below compliance threshold "
                f"({self._compliance_threshold}%)"
            )
        if avg_compliance_score < self._compliance_threshold:
            recs.append(
                f"Avg compliance score {avg_compliance_score}% below threshold "
                f"({self._compliance_threshold}%)"
            )
        if not recs:
            recs.append("Audit report compliance scores are healthy")
        return AuditReportReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            non_compliant_count=non_compliant_count,
            avg_compliance_score=avg_compliance_score,
            by_type=by_type,
            by_status=by_status,
            by_outcome=by_outcome,
            top_issues=top_issues,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("audit_report_generator_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            key = r.report_type.value
            type_dist[key] = type_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "compliance_threshold": self._compliance_threshold,
            "report_type_distribution": type_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
