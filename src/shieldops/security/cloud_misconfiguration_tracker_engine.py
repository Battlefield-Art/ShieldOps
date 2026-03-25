"""Cloud Misconfiguration Tracker Engine — track cloud misconfigurations across providers."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CloudProvider(StrEnum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    KUBERNETES = "kubernetes"
    MULTI_CLOUD = "multi_cloud"


class MisconfigCategory(StrEnum):
    ENCRYPTION = "encryption"
    ACCESS_CONTROL = "access_control"
    NETWORKING = "networking"
    LOGGING = "logging"
    IDENTITY = "identity"


class ComplianceImpact(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


# --- Models ---


class CloudMisconfigurationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource_id: str = ""
    cloud_provider: CloudProvider = CloudProvider.AWS
    misconfig_category: MisconfigCategory = MisconfigCategory.ENCRYPTION
    compliance_impact: ComplianceImpact = ComplianceImpact.NONE
    cis_control: str = ""
    auto_remediated: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CloudMisconfigurationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    cloud_provider: CloudProvider = CloudProvider.AWS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CloudMisconfigurationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_cloud_provider: dict[str, int] = Field(default_factory=dict)
    by_misconfig_category: dict[str, int] = Field(default_factory=dict)
    by_compliance_impact: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CloudMisconfigurationTrackerEngine:
    """Cloud Misconfiguration Tracker Engine — track cloud misconfigurations across providers."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = risk_threshold
        self._records: list[CloudMisconfigurationRecord] = []
        self._analyses: list[CloudMisconfigurationAnalysis] = []
        logger.info(
            "cloud_misconfiguration_tracker_engine.initialized",
            max_records=max_records,
            risk_threshold=risk_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        resource_id: str,
        cloud_provider: CloudProvider = CloudProvider.AWS,
        misconfig_category: MisconfigCategory = MisconfigCategory.ENCRYPTION,
        compliance_impact: ComplianceImpact = ComplianceImpact.NONE,
        cis_control: str = "",
        auto_remediated: bool = False,
        service: str = "",
        team: str = "",
    ) -> CloudMisconfigurationRecord:
        record = CloudMisconfigurationRecord(
            resource_id=resource_id,
            cloud_provider=cloud_provider,
            misconfig_category=misconfig_category,
            compliance_impact=compliance_impact,
            cis_control=cis_control,
            auto_remediated=auto_remediated,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "cloud_misconfiguration_tracker_engine.record_added",
            record_id=record.id,
            resource_id=resource_id,
            cloud_provider=cloud_provider.value,
            misconfig_category=misconfig_category.value,
        )
        return record

    def get_record(self, record_id: str) -> CloudMisconfigurationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        cloud_provider: CloudProvider | None = None,
        misconfig_category: MisconfigCategory | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CloudMisconfigurationRecord]:
        results = list(self._records)
        if cloud_provider is not None:
            results = [r for r in results if r.cloud_provider == cloud_provider]
        if misconfig_category is not None:
            results = [r for r in results if r.misconfig_category == misconfig_category]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        cloud_provider: CloudProvider = CloudProvider.AWS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CloudMisconfigurationAnalysis:
        analysis = CloudMisconfigurationAnalysis(
            name=name,
            cloud_provider=cloud_provider,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "cloud_misconfiguration_tracker_engine.analysis_added",
            name=name,
            cloud_provider=cloud_provider.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_provider_distribution(self) -> dict[str, Any]:
        provider_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.cloud_provider.value
            score = (
                1.0
                if r.compliance_impact in (ComplianceImpact.CRITICAL, ComplianceImpact.HIGH)
                else 0.0
            )
            provider_data.setdefault(key, []).append(score)
        result: dict[str, Any] = {}
        for k, scores in provider_data.items():
            result[k] = {
                "count": len(scores),
                "critical_pct": round(sum(scores) / len(scores) * 100, 2),
            }
        return result

    def identify_critical_misconfigs(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if (
                r.compliance_impact in (ComplianceImpact.CRITICAL, ComplianceImpact.HIGH)
                and not r.auto_remediated
            ):
                results.append(
                    {
                        "record_id": r.id,
                        "resource_id": r.resource_id,
                        "cloud_provider": r.cloud_provider.value,
                        "misconfig_category": r.misconfig_category.value,
                        "compliance_impact": r.compliance_impact.value,
                        "cis_control": r.cis_control,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(
            results,
            key=lambda x: 0 if x["compliance_impact"] == "critical" else 1,
        )

    def detect_remediation_trends(self) -> dict[str, Any]:
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

    def generate_report(self) -> CloudMisconfigurationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.cloud_provider.value] = by_e1.get(r.cloud_provider.value, 0) + 1
            by_e2[r.misconfig_category.value] = by_e2.get(r.misconfig_category.value, 0) + 1
            by_e3[r.compliance_impact.value] = by_e3.get(r.compliance_impact.value, 0) + 1
        critical_count = sum(
            1
            for r in self._records
            if r.compliance_impact in (ComplianceImpact.CRITICAL, ComplianceImpact.HIGH)
        )
        remediated = sum(1 for r in self._records if r.auto_remediated)
        remediation_pct = round(remediated / len(self._records) * 100, 2) if self._records else 0.0
        gaps = self.identify_critical_misconfigs()
        top_gaps = [g["resource_id"] for g in gaps[:5]]
        recs: list[str] = []
        if critical_count > 0:
            recs.append(f"{critical_count} critical/high misconfiguration(s) detected")
        if remediation_pct < self._threshold:
            recs.append(
                f"Auto-remediation rate {remediation_pct}% below threshold ({self._threshold}%)"
            )
        if not recs:
            recs.append("Cloud Misconfiguration Tracker Engine is healthy")
        return CloudMisconfigurationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=critical_count,
            avg_score=remediation_pct,
            by_cloud_provider=by_e1,
            by_misconfig_category=by_e2,
            by_compliance_impact=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("cloud_misconfiguration_tracker_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.cloud_provider.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "risk_threshold": self._threshold,
            "cloud_provider_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
