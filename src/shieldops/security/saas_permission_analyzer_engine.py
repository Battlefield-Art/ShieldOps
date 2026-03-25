"""SaaS Permission Analyzer Engine — analyze SaaS app permission grants and entitlements."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SaaSProvider(StrEnum):
    GOOGLE = "google"
    MICROSOFT = "microsoft"
    GITHUB = "github"
    SLACK = "slack"
    SALESFORCE = "salesforce"


class PermissionLevel(StrEnum):
    ADMIN = "admin"
    WRITE = "write"
    READ = "read"
    MINIMAL = "minimal"
    NONE = "none"


class EntitlementStatus(StrEnum):
    ACTIVE = "active"
    STALE = "stale"
    EXCESSIVE = "excessive"
    APPROPRIATE = "appropriate"
    REVOKED = "revoked"


# --- Models ---


class SaaSPermissionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    app_id: str = ""
    saas_provider: SaaSProvider = SaaSProvider.GOOGLE
    permission_level: PermissionLevel = PermissionLevel.READ
    entitlement_status: EntitlementStatus = EntitlementStatus.ACTIVE
    granted_to: str = ""
    scope_count: int = 0
    last_reviewed: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class SaaSPermissionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    app_id: str = ""
    saas_provider: SaaSProvider = SaaSProvider.GOOGLE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SaaSPermissionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_scope_count: float = 0.0
    by_saas_provider: dict[str, int] = Field(default_factory=dict)
    by_permission_level: dict[str, int] = Field(default_factory=dict)
    by_entitlement_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class SaaSPermissionAnalyzerEngine:
    """Analyze SaaS app permission grants and entitlements."""

    def __init__(
        self,
        max_records: int = 200000,
        permission_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = permission_threshold
        self._records: list[SaaSPermissionRecord] = []
        self._analyses: list[SaaSPermissionAnalysis] = []
        logger.info(
            "saas_permission_analyzer_engine.initialized",
            max_records=max_records,
            permission_threshold=permission_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        app_id: str,
        saas_provider: SaaSProvider = SaaSProvider.GOOGLE,
        permission_level: PermissionLevel = PermissionLevel.READ,
        entitlement_status: EntitlementStatus = EntitlementStatus.ACTIVE,
        granted_to: str = "",
        scope_count: int = 0,
        last_reviewed: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> SaaSPermissionRecord:
        record = SaaSPermissionRecord(
            app_id=app_id,
            saas_provider=saas_provider,
            permission_level=permission_level,
            entitlement_status=entitlement_status,
            granted_to=granted_to,
            scope_count=scope_count,
            last_reviewed=last_reviewed,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "saas_permission_analyzer_engine.record_added",
            record_id=record.id,
            app_id=app_id,
            saas_provider=saas_provider.value,
            permission_level=permission_level.value,
        )
        return record

    def get_record(self, record_id: str) -> SaaSPermissionRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        saas_provider: SaaSProvider | None = None,
        permission_level: PermissionLevel | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[SaaSPermissionRecord]:
        results = list(self._records)
        if saas_provider is not None:
            results = [r for r in results if r.saas_provider == saas_provider]
        if permission_level is not None:
            results = [r for r in results if r.permission_level == permission_level]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        app_id: str,
        saas_provider: SaaSProvider = SaaSProvider.GOOGLE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> SaaSPermissionAnalysis:
        analysis = SaaSPermissionAnalysis(
            app_id=app_id,
            saas_provider=saas_provider,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "saas_permission_analyzer_engine.analysis_added",
            app_id=app_id,
            saas_provider=saas_provider.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_permission_distribution(self) -> dict[str, Any]:
        """Analyze permission level distribution across SaaS providers."""
        provider_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = r.saas_provider.value
            provider_data.setdefault(key, {})
            lvl = r.permission_level.value
            provider_data[key][lvl] = provider_data[key].get(lvl, 0) + 1
        result: dict[str, Any] = {}
        for provider, levels in provider_data.items():
            total = sum(levels.values())
            admin_pct = round(levels.get("admin", 0) / total * 100, 2) if total else 0.0
            result[provider] = {
                "total": total,
                "levels": levels,
                "admin_percentage": admin_pct,
                "above_threshold": admin_pct > self._threshold,
            }
        return result

    def identify_excessive_permissions(self) -> list[dict[str, Any]]:
        """Identify grants with excessive or stale entitlements."""
        excessive: list[dict[str, Any]] = []
        for r in self._records:
            if r.entitlement_status in (
                EntitlementStatus.EXCESSIVE,
                EntitlementStatus.STALE,
            ):
                excessive.append(
                    {
                        "record_id": r.id,
                        "app_id": r.app_id,
                        "saas_provider": r.saas_provider.value,
                        "permission_level": r.permission_level.value,
                        "entitlement_status": r.entitlement_status.value,
                        "granted_to": r.granted_to,
                        "scope_count": r.scope_count,
                        "service": r.service,
                    }
                )
        return sorted(excessive, key=lambda x: x["scope_count"], reverse=True)

    def detect_permission_trends(self) -> list[dict[str, Any]]:
        """Detect trends in permission grants over time."""
        buckets: dict[str, list[SaaSPermissionRecord]] = {}
        for r in self._records:
            day = time.strftime("%Y-%m-%d", time.gmtime(r.created_at))
            buckets.setdefault(day, []).append(r)
        trends: list[dict[str, Any]] = []
        for day, records in sorted(buckets.items()):
            admin_ct = sum(1 for r in records if r.permission_level == PermissionLevel.ADMIN)
            excessive_ct = sum(
                1 for r in records if r.entitlement_status == EntitlementStatus.EXCESSIVE
            )
            trends.append(
                {
                    "date": day,
                    "total_grants": len(records),
                    "admin_grants": admin_ct,
                    "excessive_grants": excessive_ct,
                }
            )
        return trends

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> SaaSPermissionReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.saas_provider.value] = by_e1.get(r.saas_provider.value, 0) + 1
            by_e2[r.permission_level.value] = by_e2.get(r.permission_level.value, 0) + 1
            by_e3[r.entitlement_status.value] = by_e3.get(r.entitlement_status.value, 0) + 1
        scopes = [r.scope_count for r in self._records]
        avg_scope = round(sum(scopes) / len(scopes), 2) if scopes else 0.0
        gap_count = sum(
            1
            for r in self._records
            if r.entitlement_status in (EntitlementStatus.EXCESSIVE, EntitlementStatus.STALE)
        )
        gap_list = self.identify_excessive_permissions()
        top_gaps = [o["app_id"] for o in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} excessive/stale entitlement(s) found")
        if not recs:
            recs.append("SaaS Permission Analyzer Engine is healthy")
        return SaaSPermissionReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_scope_count=avg_scope,
            by_saas_provider=by_e1,
            by_permission_level=by_e2,
            by_entitlement_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("saas_permission_analyzer_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.saas_provider.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "saas_provider_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
