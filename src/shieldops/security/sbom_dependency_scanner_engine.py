"""SBOM Dependency Scanner Engine — track SBOM generation and dependency vulnerability scanning."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class Ecosystem(StrEnum):
    NPM = "npm"
    PIP = "pip"
    MAVEN = "maven"
    GO = "go"
    CARGO = "cargo"


class LicenseRisk(StrEnum):
    COPYLEFT = "copyleft"
    PERMISSIVE = "permissive"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"
    DUAL = "dual"


class DepStatus(StrEnum):
    CURRENT = "current"
    OUTDATED = "outdated"
    VULNERABLE = "vulnerable"
    DEPRECATED = "deprecated"
    ABANDONED = "abandoned"


# --- Models ---


class SBOMDependencyRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    package_name: str = ""
    ecosystem: Ecosystem = Ecosystem.NPM
    license_risk: LicenseRisk = LicenseRisk.PERMISSIVE
    dep_status: DepStatus = DepStatus.CURRENT
    vulnerabilities: int = 0
    versions_behind: int = 0
    direct: bool = True
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class SBOMDependencyAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    ecosystem: Ecosystem = Ecosystem.NPM
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SBOMDependencyReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_ecosystem: dict[str, int] = Field(default_factory=dict)
    by_license_risk: dict[str, int] = Field(default_factory=dict)
    by_dep_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class SBOMDependencyScannerEngine:
    """SBOM Dependency Scanner Engine — track SBOM and dependency vulnerabilities."""

    def __init__(
        self,
        max_records: int = 200000,
        vuln_threshold: float = 5.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = vuln_threshold
        self._records: list[SBOMDependencyRecord] = []
        self._analyses: list[SBOMDependencyAnalysis] = []
        logger.info(
            "sbom_dependency_scanner_engine.initialized",
            max_records=max_records,
            vuln_threshold=vuln_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        package_name: str,
        ecosystem: Ecosystem = Ecosystem.NPM,
        license_risk: LicenseRisk = LicenseRisk.PERMISSIVE,
        dep_status: DepStatus = DepStatus.CURRENT,
        vulnerabilities: int = 0,
        versions_behind: int = 0,
        direct: bool = True,
        service: str = "",
        team: str = "",
    ) -> SBOMDependencyRecord:
        record = SBOMDependencyRecord(
            package_name=package_name,
            ecosystem=ecosystem,
            license_risk=license_risk,
            dep_status=dep_status,
            vulnerabilities=vulnerabilities,
            versions_behind=versions_behind,
            direct=direct,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "sbom_dependency_scanner_engine.record_added",
            record_id=record.id,
            package_name=package_name,
            ecosystem=ecosystem.value,
            dep_status=dep_status.value,
        )
        return record

    def get_record(self, record_id: str) -> SBOMDependencyRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        ecosystem: Ecosystem | None = None,
        dep_status: DepStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[SBOMDependencyRecord]:
        results = list(self._records)
        if ecosystem is not None:
            results = [r for r in results if r.ecosystem == ecosystem]
        if dep_status is not None:
            results = [r for r in results if r.dep_status == dep_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        ecosystem: Ecosystem = Ecosystem.NPM,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> SBOMDependencyAnalysis:
        analysis = SBOMDependencyAnalysis(
            name=name,
            ecosystem=ecosystem,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "sbom_dependency_scanner_engine.analysis_added",
            name=name,
            ecosystem=ecosystem.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_ecosystem_distribution(self) -> dict[str, Any]:
        eco_data: dict[str, list[int]] = {}
        for r in self._records:
            key = r.ecosystem.value
            eco_data.setdefault(key, []).append(r.vulnerabilities)
        result: dict[str, Any] = {}
        for k, vulns in eco_data.items():
            result[k] = {
                "count": len(vulns),
                "avg_vulns": round(sum(vulns) / len(vulns), 2),
            }
        return result

    def identify_vulnerable_dependencies(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.vulnerabilities >= self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "package_name": r.package_name,
                        "ecosystem": r.ecosystem.value,
                        "vulnerabilities": r.vulnerabilities,
                        "dep_status": r.dep_status.value,
                        "license_risk": r.license_risk.value,
                        "direct": r.direct,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["vulnerabilities"], reverse=True)

    def detect_update_trends(self) -> dict[str, Any]:
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [a.analysis_score for a in self._analyses]
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

    def generate_report(self) -> SBOMDependencyReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.ecosystem.value] = by_e1.get(r.ecosystem.value, 0) + 1
            by_e2[r.license_risk.value] = by_e2.get(r.license_risk.value, 0) + 1
            by_e3[r.dep_status.value] = by_e3.get(r.dep_status.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.vulnerabilities >= self._threshold)
        vulns = [r.vulnerabilities for r in self._records]
        avg_score = round(sum(vulns) / len(vulns), 2) if vulns else 0.0
        gap_list = self.identify_vulnerable_dependencies()
        top_gaps = [g["package_name"] for g in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} dependency(ies) above vuln threshold ({self._threshold})")
        if self._records and avg_score >= self._threshold:
            recs.append(f"Avg vulns {avg_score} at/above threshold ({self._threshold})")
        if not recs:
            recs.append("SBOM Dependency Scanner Engine is healthy")
        return SBOMDependencyReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_ecosystem=by_e1,
            by_license_risk=by_e2,
            by_dep_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("sbom_dependency_scanner_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.ecosystem.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "vuln_threshold": self._threshold,
            "ecosystem_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
