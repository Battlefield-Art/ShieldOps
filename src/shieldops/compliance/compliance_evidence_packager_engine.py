"""Compliance Evidence Packager Engine — track evidence collection and packaging for audits."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EvidenceType(StrEnum):
    LOG_EXPORT = "log_export"
    CONFIG_SNAPSHOT = "config_snapshot"
    POLICY_DOCUMENT = "policy_document"
    SCAN_RESULT = "scan_result"
    ACCESS_REVIEW = "access_review"


class ComplianceFramework(StrEnum):
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    FEDRAMP = "fedramp"
    GDPR = "gdpr"
    ISO_27001 = "iso_27001"


class PackagingStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    MISSING = "missing"
    EXPIRED = "expired"
    PENDING = "pending"


# --- Models ---


class EvidenceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    control_id: str = ""
    evidence_type: EvidenceType = EvidenceType.LOG_EXPORT
    compliance_framework: ComplianceFramework = ComplianceFramework.SOC2
    packaging_status: PackagingStatus = PackagingStatus.COMPLETE
    completeness_score: float = 0.0
    artifact_count: int = 0
    hash_verified: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class EvidenceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    control_id: str = ""
    evidence_type: EvidenceType = EvidenceType.LOG_EXPORT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class EvidenceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    missing_count: int = 0
    avg_completeness: float = 0.0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_framework: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ComplianceEvidencePackagerEngine:
    """Track evidence collection and packaging for compliance audits."""

    def __init__(
        self,
        max_records: int = 200000,
        completeness_threshold: float = 90.0,
    ) -> None:
        self._max_records = max_records
        self._completeness_threshold = completeness_threshold
        self._records: list[EvidenceRecord] = []
        self._analyses: list[EvidenceAnalysis] = []
        logger.info(
            "compliance_evidence_packager_engine.initialized",
            max_records=max_records,
            completeness_threshold=completeness_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        control_id: str,
        evidence_type: EvidenceType = EvidenceType.LOG_EXPORT,
        compliance_framework: ComplianceFramework = ComplianceFramework.SOC2,
        packaging_status: PackagingStatus = PackagingStatus.COMPLETE,
        completeness_score: float = 0.0,
        artifact_count: int = 0,
        hash_verified: bool = False,
        service: str = "",
        team: str = "",
    ) -> EvidenceRecord:
        record = EvidenceRecord(
            control_id=control_id,
            evidence_type=evidence_type,
            compliance_framework=compliance_framework,
            packaging_status=packaging_status,
            completeness_score=completeness_score,
            artifact_count=artifact_count,
            hash_verified=hash_verified,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "compliance_evidence_packager_engine.record_added",
            record_id=record.id,
            control_id=control_id,
            compliance_framework=compliance_framework.value,
        )
        return record

    def get_record(self, record_id: str) -> EvidenceRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        evidence_type: EvidenceType | None = None,
        compliance_framework: ComplianceFramework | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[EvidenceRecord]:
        results = list(self._records)
        if evidence_type is not None:
            results = [r for r in results if r.evidence_type == evidence_type]
        if compliance_framework is not None:
            results = [r for r in results if r.compliance_framework == compliance_framework]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        control_id: str,
        evidence_type: EvidenceType = EvidenceType.LOG_EXPORT,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> EvidenceAnalysis:
        analysis = EvidenceAnalysis(
            control_id=control_id,
            evidence_type=evidence_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "compliance_evidence_packager_engine.analysis_added",
            control_id=control_id,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_evidence_coverage(self) -> dict[str, Any]:
        """Group by compliance_framework; return count and avg completeness."""
        fw_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.compliance_framework.value
            fw_data.setdefault(key, []).append(r.completeness_score)
        result: dict[str, Any] = {}
        for fw, scores in fw_data.items():
            result[fw] = {
                "count": len(scores),
                "avg_completeness": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_missing_evidence(self) -> list[dict[str, Any]]:
        """Return records where completeness_score < threshold or status is MISSING."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if (
                r.completeness_score < self._completeness_threshold
                or r.packaging_status == PackagingStatus.MISSING
            ):
                results.append(
                    {
                        "record_id": r.id,
                        "control_id": r.control_id,
                        "evidence_type": r.evidence_type.value,
                        "compliance_framework": r.compliance_framework.value,
                        "completeness_score": r.completeness_score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["completeness_score"])

    def detect_collection_trends(self) -> dict[str, Any]:
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

    def generate_report(self) -> EvidenceReport:
        by_type: dict[str, int] = {}
        by_framework: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for r in self._records:
            by_type[r.evidence_type.value] = by_type.get(r.evidence_type.value, 0) + 1
            by_framework[r.compliance_framework.value] = (
                by_framework.get(r.compliance_framework.value, 0) + 1
            )
            by_status[r.packaging_status.value] = by_status.get(r.packaging_status.value, 0) + 1
        missing_count = sum(
            1
            for r in self._records
            if r.packaging_status == PackagingStatus.MISSING
            or r.completeness_score < self._completeness_threshold
        )
        scores = [r.completeness_score for r in self._records]
        avg_completeness = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_missing_evidence()
        top_gaps = [g["control_id"] for g in gap_list[:5]]
        recs: list[str] = []
        if missing_count > 0:
            recs.append(f"{missing_count} control(s) have incomplete or missing evidence")
        if avg_completeness < self._completeness_threshold:
            recs.append(
                f"Avg evidence completeness {avg_completeness}% below threshold "
                f"({self._completeness_threshold}%)"
            )
        if not recs:
            recs.append("Compliance evidence collection is complete and healthy")
        return EvidenceReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            missing_count=missing_count,
            avg_completeness=avg_completeness,
            by_type=by_type,
            by_framework=by_framework,
            by_status=by_status,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("compliance_evidence_packager_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        fw_dist: dict[str, int] = {}
        for r in self._records:
            key = r.compliance_framework.value
            fw_dist[key] = fw_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "completeness_threshold": self._completeness_threshold,
            "framework_distribution": fw_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
