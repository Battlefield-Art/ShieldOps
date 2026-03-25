"""Credential Leak Analyzer Engine — analyze credential leak patterns and sources."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class LeakSource(StrEnum):
    PUBLIC_REPO = "public_repo"
    PASTE_SITE = "paste_site"
    DARK_WEB = "dark_web"
    LOG_AGGREGATOR = "log_aggregator"
    CHAT_PLATFORM = "chat_platform"


class CredentialAge(StrEnum):
    CURRENT = "current"
    RECENT = "recent"
    STALE = "stale"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class LeakImpact(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


# --- Models ---


class CredentialLeakRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    leak_id: str = ""
    leak_source: LeakSource = LeakSource.PUBLIC_REPO
    credential_age: CredentialAge = CredentialAge.UNKNOWN
    leak_impact: LeakImpact = LeakImpact.MEDIUM
    affected_service: str = ""
    affected_accounts: int = 0
    days_exposed: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CredentialLeakAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    leak_id: str = ""
    leak_source: LeakSource = LeakSource.PUBLIC_REPO
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CredentialLeakReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_days_exposed: float = 0.0
    by_leak_source: dict[str, int] = Field(default_factory=dict)
    by_credential_age: dict[str, int] = Field(default_factory=dict)
    by_leak_impact: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CredentialLeakAnalyzerEngine:
    """Analyze credential leak patterns and sources."""

    def __init__(
        self,
        max_records: int = 200000,
        impact_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = impact_threshold
        self._records: list[CredentialLeakRecord] = []
        self._analyses: list[CredentialLeakAnalysis] = []
        logger.info(
            "credential_leak_analyzer_engine.initialized",
            max_records=max_records,
            impact_threshold=impact_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        leak_id: str,
        leak_source: LeakSource = LeakSource.PUBLIC_REPO,
        credential_age: CredentialAge = CredentialAge.UNKNOWN,
        leak_impact: LeakImpact = LeakImpact.MEDIUM,
        affected_service: str = "",
        affected_accounts: int = 0,
        days_exposed: int = 0,
        service: str = "",
        team: str = "",
    ) -> CredentialLeakRecord:
        record = CredentialLeakRecord(
            leak_id=leak_id,
            leak_source=leak_source,
            credential_age=credential_age,
            leak_impact=leak_impact,
            affected_service=affected_service,
            affected_accounts=affected_accounts,
            days_exposed=days_exposed,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "credential_leak_analyzer_engine.record_added",
            record_id=record.id,
            leak_id=leak_id,
            leak_source=leak_source.value,
            leak_impact=leak_impact.value,
        )
        return record

    def get_record(self, record_id: str) -> CredentialLeakRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        leak_source: LeakSource | None = None,
        leak_impact: LeakImpact | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CredentialLeakRecord]:
        results = list(self._records)
        if leak_source is not None:
            results = [r for r in results if r.leak_source == leak_source]
        if leak_impact is not None:
            results = [r for r in results if r.leak_impact == leak_impact]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        leak_id: str,
        leak_source: LeakSource = LeakSource.PUBLIC_REPO,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CredentialLeakAnalysis:
        analysis = CredentialLeakAnalysis(
            leak_id=leak_id,
            leak_source=leak_source,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "credential_leak_analyzer_engine.analysis_added",
            leak_id=leak_id,
            leak_source=leak_source.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_leak_sources(self) -> dict[str, Any]:
        """Analyze leak distribution by source and impact."""
        source_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = r.leak_source.value
            source_data.setdefault(key, {})
            imp = r.leak_impact.value
            source_data[key][imp] = source_data[key].get(imp, 0) + 1
        result: dict[str, Any] = {}
        for source, impacts in source_data.items():
            total = sum(impacts.values())
            critical_ct = impacts.get("critical", 0) + impacts.get("high", 0)
            severity_pct = round(critical_ct / total * 100, 2) if total else 0.0
            result[source] = {
                "total": total,
                "impacts": impacts,
                "critical_high_pct": severity_pct,
                "above_threshold": severity_pct > self._threshold,
            }
        return result

    def identify_critical_leaks(self) -> list[dict[str, Any]]:
        """Identify critical and high impact credential leaks."""
        critical: list[dict[str, Any]] = []
        for r in self._records:
            if r.leak_impact in (LeakImpact.CRITICAL, LeakImpact.HIGH):
                critical.append(
                    {
                        "record_id": r.id,
                        "leak_id": r.leak_id,
                        "leak_source": r.leak_source.value,
                        "credential_age": r.credential_age.value,
                        "leak_impact": r.leak_impact.value,
                        "affected_service": r.affected_service,
                        "affected_accounts": r.affected_accounts,
                        "days_exposed": r.days_exposed,
                        "service": r.service,
                    }
                )
        return sorted(critical, key=lambda x: x["days_exposed"], reverse=True)

    def detect_leak_trends(self) -> list[dict[str, Any]]:
        """Detect trends in credential leaks over time."""
        buckets: dict[str, list[CredentialLeakRecord]] = {}
        for r in self._records:
            day = time.strftime("%Y-%m-%d", time.gmtime(r.created_at))
            buckets.setdefault(day, []).append(r)
        trends: list[dict[str, Any]] = []
        for day, records in sorted(buckets.items()):
            critical_ct = sum(
                1 for r in records if r.leak_impact in (LeakImpact.CRITICAL, LeakImpact.HIGH)
            )
            total_accounts = sum(r.affected_accounts for r in records)
            trends.append(
                {
                    "date": day,
                    "total_leaks": len(records),
                    "critical_high": critical_ct,
                    "total_affected_accounts": total_accounts,
                }
            )
        return trends

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> CredentialLeakReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.leak_source.value] = by_e1.get(r.leak_source.value, 0) + 1
            by_e2[r.credential_age.value] = by_e2.get(r.credential_age.value, 0) + 1
            by_e3[r.leak_impact.value] = by_e3.get(r.leak_impact.value, 0) + 1
        days = [r.days_exposed for r in self._records]
        avg_days = round(sum(days) / len(days), 2) if days else 0.0
        gap_count = sum(
            1 for r in self._records if r.leak_impact in (LeakImpact.CRITICAL, LeakImpact.HIGH)
        )
        gap_list = self.identify_critical_leaks()
        top_gaps = [o["leak_id"] for o in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} critical/high impact leak(s) detected")
        if not recs:
            recs.append("Credential Leak Analyzer Engine is healthy")
        return CredentialLeakReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_days_exposed=avg_days,
            by_leak_source=by_e1,
            by_credential_age=by_e2,
            by_leak_impact=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("credential_leak_analyzer_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.leak_source.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "leak_source_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
