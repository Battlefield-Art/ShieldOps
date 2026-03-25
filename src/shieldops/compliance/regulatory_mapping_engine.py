"""Regulatory Mapping Engine — map data findings to regulatory requirements."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MappingStatus(StrEnum):
    MAPPED = "mapped"
    UNMAPPED = "unmapped"
    PARTIAL = "partial"
    EXEMPT = "exempt"
    DISPUTED = "disputed"


class ComplianceOutcome(StrEnum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    REMEDIATION_NEEDED = "remediation_needed"
    PENDING_REVIEW = "pending_review"
    EXEMPT = "exempt"


class RegulationScope(StrEnum):
    GLOBAL = "global"
    US_FEDERAL = "us_federal"
    US_STATE = "us_state"
    EU = "eu"
    INDUSTRY = "industry"


# --- Models ---


class RegulatoryMappingRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""
    mapping_status: MappingStatus = MappingStatus.UNMAPPED
    compliance_outcome: ComplianceOutcome = ComplianceOutcome.PENDING_REVIEW
    regulation_scope: RegulationScope = RegulationScope.GLOBAL
    regulation: str = ""
    requirement: str = ""
    gap_count: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class RegulatoryMappingAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""
    mapping_status: MappingStatus = MappingStatus.UNMAPPED
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RegulatoryMappingReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_mapping_status: dict[str, int] = Field(default_factory=dict)
    by_compliance_outcome: dict[str, int] = Field(default_factory=dict)
    by_regulation_scope: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class RegulatoryMappingEngine:
    """Map data findings to regulatory requirements and track compliance."""

    def __init__(
        self,
        max_records: int = 200000,
        compliance_threshold: float = 90.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = compliance_threshold
        self._records: list[RegulatoryMappingRecord] = []
        self._analyses: list[RegulatoryMappingAnalysis] = []
        logger.info(
            "regulatory_mapping_engine.initialized",
            max_records=max_records,
            compliance_threshold=compliance_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        finding_id: str,
        mapping_status: MappingStatus = MappingStatus.UNMAPPED,
        compliance_outcome: ComplianceOutcome = ComplianceOutcome.PENDING_REVIEW,
        regulation_scope: RegulationScope = RegulationScope.GLOBAL,
        regulation: str = "",
        requirement: str = "",
        gap_count: int = 0,
        service: str = "",
        team: str = "",
    ) -> RegulatoryMappingRecord:
        record = RegulatoryMappingRecord(
            finding_id=finding_id,
            mapping_status=mapping_status,
            compliance_outcome=compliance_outcome,
            regulation_scope=regulation_scope,
            regulation=regulation,
            requirement=requirement,
            gap_count=gap_count,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "regulatory_mapping_engine.record_added",
            record_id=record.id,
            finding_id=finding_id,
            mapping_status=mapping_status.value,
            compliance_outcome=compliance_outcome.value,
        )
        return record

    def get_record(self, record_id: str) -> RegulatoryMappingRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        mapping_status: MappingStatus | None = None,
        compliance_outcome: ComplianceOutcome | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[RegulatoryMappingRecord]:
        results = list(self._records)
        if mapping_status is not None:
            results = [r for r in results if r.mapping_status == mapping_status]
        if compliance_outcome is not None:
            results = [r for r in results if r.compliance_outcome == compliance_outcome]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        finding_id: str,
        mapping_status: MappingStatus = MappingStatus.UNMAPPED,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> RegulatoryMappingAnalysis:
        analysis = RegulatoryMappingAnalysis(
            finding_id=finding_id,
            mapping_status=mapping_status,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "regulatory_mapping_engine.analysis_added",
            finding_id=finding_id,
            mapping_status=mapping_status.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_regulatory_coverage(self) -> list[dict[str, Any]]:
        """Analyze regulatory coverage across regulations."""
        reg_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            reg = r.regulation or "unknown"
            reg_data.setdefault(reg, {"total": 0, "mapped": 0, "compliant": 0})
            reg_data[reg]["total"] += 1
            if r.mapping_status == MappingStatus.MAPPED:
                reg_data[reg]["mapped"] += 1
            if r.compliance_outcome == ComplianceOutcome.COMPLIANT:
                reg_data[reg]["compliant"] += 1
        results: list[dict[str, Any]] = []
        for reg, stats in reg_data.items():
            total = stats["total"]
            coverage_pct = round(stats["mapped"] / total * 100, 2) if total > 0 else 0.0
            compliance_pct = round(stats["compliant"] / total * 100, 2) if total > 0 else 0.0
            results.append(
                {
                    "regulation": reg,
                    "total_findings": total,
                    "mapped_count": stats["mapped"],
                    "coverage_pct": coverage_pct,
                    "compliance_pct": compliance_pct,
                }
            )
        return sorted(results, key=lambda x: x["coverage_pct"])

    def identify_compliance_gaps(self) -> list[dict[str, Any]]:
        """Identify findings with compliance gaps."""
        gaps: list[dict[str, Any]] = []
        for r in self._records:
            if r.compliance_outcome in (
                ComplianceOutcome.NON_COMPLIANT,
                ComplianceOutcome.REMEDIATION_NEEDED,
            ):
                gaps.append(
                    {
                        "record_id": r.id,
                        "finding_id": r.finding_id,
                        "regulation": r.regulation,
                        "requirement": r.requirement,
                        "compliance_outcome": r.compliance_outcome.value,
                        "mapping_status": r.mapping_status.value,
                        "gap_count": r.gap_count,
                        "service": r.service,
                    }
                )
        return sorted(gaps, key=lambda x: x["gap_count"], reverse=True)

    def detect_mapping_trends(self) -> list[dict[str, Any]]:
        """Detect mapping status trends by regulation scope."""
        scope_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            scope = r.regulation_scope.value
            scope_data.setdefault(scope, {})
            ms = r.mapping_status.value
            scope_data[scope][ms] = scope_data[scope].get(ms, 0) + 1
        results: list[dict[str, Any]] = []
        for scope, statuses in scope_data.items():
            total = sum(statuses.values())
            mapped_pct = round(statuses.get("mapped", 0) / total * 100, 2) if total > 0 else 0.0
            results.append(
                {
                    "regulation_scope": scope,
                    "status_distribution": statuses,
                    "total_findings": total,
                    "mapped_pct": mapped_pct,
                    "unmapped_count": statuses.get("unmapped", 0),
                }
            )
        return sorted(results, key=lambda x: x["mapped_pct"])

    # -- standard methods ---------------------------------------------------

    def generate_report(self) -> RegulatoryMappingReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.mapping_status.value] = by_e1.get(r.mapping_status.value, 0) + 1
            by_e2[r.compliance_outcome.value] = by_e2.get(r.compliance_outcome.value, 0) + 1
            by_e3[r.regulation_scope.value] = by_e3.get(r.regulation_scope.value, 0) + 1
        compliance_scores = {
            ComplianceOutcome.COMPLIANT: 100,
            ComplianceOutcome.EXEMPT: 100,
            ComplianceOutcome.PENDING_REVIEW: 50,
            ComplianceOutcome.REMEDIATION_NEEDED: 25,
            ComplianceOutcome.NON_COMPLIANT: 0,
        }
        scores = [compliance_scores.get(r.compliance_outcome, 50) for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gaps = self.identify_compliance_gaps()
        gap_count = len(gaps)
        top_gaps = [o["finding_id"] for o in gaps[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} compliance gap(s) identified")
        if avg_score < self._threshold:
            recs.append(f"Avg compliance score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Regulatory Mapping Engine is healthy")
        return RegulatoryMappingReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_mapping_status=by_e1,
            by_compliance_outcome=by_e2,
            by_regulation_scope=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("regulatory_mapping_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.mapping_status.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "compliance_threshold": self._threshold,
            "mapping_status_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
