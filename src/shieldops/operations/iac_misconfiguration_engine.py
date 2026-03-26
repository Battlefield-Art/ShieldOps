"""IaC Misconfiguration Engine — detect, map to benchmarks, auto-suggest fixes."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class IaCPlatform(StrEnum):
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    PULUMI = "pulumi"
    ANSIBLE = "ansible"
    HELM = "helm"


class MisconfigCategory(StrEnum):
    OPEN_SECURITY_GROUP = "open_security_group"
    UNENCRYPTED_STORAGE = "unencrypted_storage"
    OVERPRIVILEGED_IAM = "overprivileged_iam"
    PUBLIC_ENDPOINT = "public_endpoint"
    MISSING_LOGGING = "missing_logging"


class ComplianceMapping(StrEnum):
    CIS_AWS = "cis_aws"
    CIS_GCP = "cis_gcp"
    CIS_AZURE = "cis_azure"
    NIST_800_53 = "nist_800_53"
    SOC2_CC = "soc2_cc"


# --- Models ---


class MisconfigRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    misconfig_name: str = ""
    iac_platform: IaCPlatform = IaCPlatform.TERRAFORM
    misconfig_category: MisconfigCategory = MisconfigCategory.OPEN_SECURITY_GROUP
    compliance_mapping: ComplianceMapping = ComplianceMapping.CIS_AWS
    severity_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class MisconfigAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    misconfig_name: str = ""
    iac_platform: IaCPlatform = IaCPlatform.TERRAFORM
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MisconfigReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    critical_count: int = 0
    avg_severity_score: float = 0.0
    by_platform: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_compliance: dict[str, int] = Field(default_factory=dict)
    top_misconfigs: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class IaCMisconfigurationEngine:
    """Detect IaC misconfigurations, map to benchmarks, auto-suggest fixes."""

    def __init__(
        self,
        max_records: int = 200000,
        severity_threshold: float = 65.0,
    ) -> None:
        self._max_records = max_records
        self._severity_threshold = severity_threshold
        self._records: list[MisconfigRecord] = []
        self._analyses: list[MisconfigAnalysis] = []
        logger.info(
            "iac_misconfiguration.initialized",
            max_records=max_records,
            severity_threshold=severity_threshold,
        )

    # -- record / get / list ----------------------------

    def add_record(
        self,
        misconfig_name: str,
        iac_platform: IaCPlatform = (IaCPlatform.TERRAFORM),
        misconfig_category: MisconfigCategory = (MisconfigCategory.OPEN_SECURITY_GROUP),
        compliance_mapping: ComplianceMapping = (ComplianceMapping.CIS_AWS),
        severity_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> MisconfigRecord:
        record = MisconfigRecord(
            misconfig_name=misconfig_name,
            iac_platform=iac_platform,
            misconfig_category=misconfig_category,
            compliance_mapping=compliance_mapping,
            severity_score=severity_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "iac_misconfiguration.record_added",
            record_id=record.id,
            misconfig_name=misconfig_name,
            iac_platform=iac_platform.value,
        )
        return record

    def get_record(self, record_id: str) -> MisconfigRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        iac_platform: IaCPlatform | None = None,
        misconfig_category: (MisconfigCategory | None) = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[MisconfigRecord]:
        results = list(self._records)
        if iac_platform is not None:
            results = [r for r in results if r.iac_platform == iac_platform]
        if misconfig_category is not None:
            results = [r for r in results if r.misconfig_category == misconfig_category]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        misconfig_name: str,
        iac_platform: IaCPlatform = (IaCPlatform.TERRAFORM),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> MisconfigAnalysis:
        analysis = MisconfigAnalysis(
            misconfig_name=misconfig_name,
            iac_platform=iac_platform,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "iac_misconfiguration.analysis_added",
            misconfig_name=misconfig_name,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ------------------------------

    def detect_misconfig(self) -> dict[str, Any]:
        """Group by iac_platform; return count and avg severity."""
        plat_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.iac_platform.value
            plat_data.setdefault(key, []).append(r.severity_score)
        result: dict[str, Any] = {}
        for plat, scores in plat_data.items():
            result[plat] = {
                "count": len(scores),
                "avg_severity": round(sum(scores) / len(scores), 2),
            }
        return result

    def map_to_benchmark(
        self,
    ) -> list[dict[str, Any]]:
        """Return records above severity threshold with compliance mapping."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.severity_score >= self._severity_threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "misconfig_name": (r.misconfig_name),
                        "compliance_mapping": (r.compliance_mapping.value),
                        "severity_score": (r.severity_score),
                        "service": r.service,
                    }
                )
        return sorted(
            results,
            key=lambda x: x["severity_score"],
            reverse=True,
        )

    def auto_suggest_fix(
        self,
    ) -> list[dict[str, Any]]:
        """Group by category, count and avg severity, sorted descending."""
        cat_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.misconfig_category.value
            cat_data.setdefault(key, []).append(r.severity_score)
        results: list[dict[str, Any]] = []
        for cat, scores in cat_data.items():
            results.append(
                {
                    "category": cat,
                    "avg_severity": round(sum(scores) / len(scores), 2),
                    "misconfig_count": len(scores),
                }
            )
        results.sort(
            key=lambda x: x["avg_severity"],
            reverse=True,
        )
        return results

    # -- report / stats ---------------------------------

    def generate_report(self) -> MisconfigReport:
        by_platform: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_compliance: dict[str, int] = {}
        for r in self._records:
            by_platform[r.iac_platform.value] = by_platform.get(r.iac_platform.value, 0) + 1
            by_category[r.misconfig_category.value] = (
                by_category.get(r.misconfig_category.value, 0) + 1
            )
            by_compliance[r.compliance_mapping.value] = (
                by_compliance.get(r.compliance_mapping.value, 0) + 1
            )
        critical_count = sum(
            1 for r in self._records if r.severity_score >= self._severity_threshold
        )
        scores = [r.severity_score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        top = [
            r.misconfig_name
            for r in sorted(
                self._records,
                key=lambda x: x.severity_score,
                reverse=True,
            )[:5]
        ]
        recs: list[str] = []
        if critical_count > 0:
            recs.append(
                f"{critical_count} misconfig(s) above"
                f" severity threshold"
                f" ({self._severity_threshold})"
            )
        if not recs:
            recs.append("IaC configurations are compliant")
        return MisconfigReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            critical_count=critical_count,
            avg_severity_score=avg,
            by_platform=by_platform,
            by_category=by_category,
            by_compliance=by_compliance,
            top_misconfigs=top,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("iac_misconfiguration.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        plat_dist: dict[str, int] = {}
        for r in self._records:
            key = r.iac_platform.value
            plat_dist[key] = plat_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "severity_threshold": (self._severity_threshold),
            "platform_distribution": plat_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
