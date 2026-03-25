"""OAuth Grant Risk Engine — track and analyze OAuth grant risk across SaaS applications."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class GrantProvider(StrEnum):
    GOOGLE_WORKSPACE = "google_workspace"
    MICROSOFT_365 = "microsoft_365"
    GITHUB = "github"
    SLACK = "slack"
    SALESFORCE = "salesforce"


class GrantRiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    COMPLIANT = "compliant"


class GrantCategory(StrEnum):
    OVERPRIVILEGED = "overprivileged"
    STALE = "stale"
    SUSPICIOUS = "suspicious"
    UNREVIEWED = "unreviewed"
    COMPLIANT = "compliant"


# --- Models ---


class GrantRiskRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    grant_id: str = ""
    grant_provider: GrantProvider = GrantProvider.GOOGLE_WORKSPACE
    grant_risk_level: GrantRiskLevel = GrantRiskLevel.COMPLIANT
    grant_category: GrantCategory = GrantCategory.COMPLIANT
    risk_score: float = 0.0
    scope_count: int = 0
    days_since_use: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class GrantRiskAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    grant_id: str = ""
    grant_provider: GrantProvider = GrantProvider.GOOGLE_WORKSPACE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class GrantRiskReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    high_risk_count: int = 0
    avg_risk_score: float = 0.0
    by_provider: dict[str, int] = Field(default_factory=dict)
    by_risk_level: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    top_risks: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OAuthGrantRiskEngine:
    """Track and analyze OAuth grant risk across SaaS applications."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._risk_threshold = risk_threshold
        self._records: list[GrantRiskRecord] = []
        self._analyses: list[GrantRiskAnalysis] = []
        logger.info(
            "oauth_grant_risk_engine.initialized",
            max_records=max_records,
            risk_threshold=risk_threshold,
        )

    def add_record(
        self,
        grant_id: str,
        grant_provider: GrantProvider = GrantProvider.GOOGLE_WORKSPACE,
        grant_risk_level: GrantRiskLevel = GrantRiskLevel.COMPLIANT,
        grant_category: GrantCategory = GrantCategory.COMPLIANT,
        risk_score: float = 0.0,
        scope_count: int = 0,
        days_since_use: int = 0,
        service: str = "",
        team: str = "",
    ) -> GrantRiskRecord:
        record = GrantRiskRecord(
            grant_id=grant_id,
            grant_provider=grant_provider,
            grant_risk_level=grant_risk_level,
            grant_category=grant_category,
            risk_score=risk_score,
            scope_count=scope_count,
            days_since_use=days_since_use,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "oauth_grant_risk_engine.record_added",
            record_id=record.id,
            grant_id=grant_id,
            grant_risk_level=grant_risk_level.value,
        )
        return record

    def get_record(self, record_id: str) -> GrantRiskRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        grant_provider: GrantProvider | None = None,
        grant_risk_level: GrantRiskLevel | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[GrantRiskRecord]:
        results = list(self._records)
        if grant_provider is not None:
            results = [r for r in results if r.grant_provider == grant_provider]
        if grant_risk_level is not None:
            results = [r for r in results if r.grant_risk_level == grant_risk_level]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        grant_id: str,
        grant_provider: GrantProvider = GrantProvider.GOOGLE_WORKSPACE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> GrantRiskAnalysis:
        analysis = GrantRiskAnalysis(
            grant_id=grant_id,
            grant_provider=grant_provider,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "oauth_grant_risk_engine.analysis_added",
            grant_id=grant_id,
            analysis_score=analysis_score,
        )
        return analysis

    def analyze_provider_distribution(self) -> dict[str, Any]:
        """Group by provider; return count and avg risk_score."""
        prov_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.grant_provider.value
            prov_data.setdefault(key, []).append(r.risk_score)
        result: dict[str, Any] = {}
        for prov, scores in prov_data.items():
            result[prov] = {
                "count": len(scores),
                "avg_risk_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_high_risk_grants(self) -> list[dict[str, Any]]:
        """Return records where risk_score > risk_threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.risk_score > self._risk_threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "grant_id": r.grant_id,
                        "grant_provider": r.grant_provider.value,
                        "risk_score": r.risk_score,
                        "grant_category": r.grant_category.value,
                        "days_since_use": r.days_since_use,
                        "service": r.service,
                    }
                )
        return sorted(results, key=lambda x: x["risk_score"], reverse=True)

    def detect_risk_trends(self) -> dict[str, Any]:
        """Split-half comparison on analysis_score; delta threshold 5.0."""
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [c.analysis_score for c in self._analyses]
        mid = len(vals) // 2
        first_half, second_half = vals[:mid], vals[mid:]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        delta = round(avg_second - avg_first, 2)
        trend = "stable" if abs(delta) < 5.0 else ("improving" if delta > 0 else "degrading")
        return {
            "trend": trend,
            "delta": delta,
            "avg_first_half": round(avg_first, 2),
            "avg_second_half": round(avg_second, 2),
        }

    def generate_report(self) -> GrantRiskReport:
        by_provider: dict[str, int] = {}
        by_risk_level: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for r in self._records:
            by_provider[r.grant_provider.value] = by_provider.get(r.grant_provider.value, 0) + 1
            by_risk_level[r.grant_risk_level.value] = (
                by_risk_level.get(r.grant_risk_level.value, 0) + 1
            )
            by_category[r.grant_category.value] = by_category.get(r.grant_category.value, 0) + 1
        high_risk_count = sum(1 for r in self._records if r.risk_score > self._risk_threshold)
        scores = [r.risk_score for r in self._records]
        avg_risk = round(sum(scores) / len(scores), 2) if scores else 0.0
        hr_list = self.identify_high_risk_grants()
        top_risks = [h["grant_id"] for h in hr_list[:5]]
        recs: list[str] = []
        if high_risk_count > 0:
            recs.append(
                f"{high_risk_count} grant(s) exceed risk threshold ({self._risk_threshold})"
            )
        stale = sum(1 for r in self._records if r.days_since_use > 90)
        if stale > 0:
            recs.append(f"{stale} grant(s) unused for >90 days — consider revocation")
        if not recs:
            recs.append("OAuth grant risk posture is healthy")
        return GrantRiskReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            high_risk_count=high_risk_count,
            avg_risk_score=avg_risk,
            by_provider=by_provider,
            by_risk_level=by_risk_level,
            by_category=by_category,
            top_risks=top_risks,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("oauth_grant_risk_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        prov_dist: dict[str, int] = {}
        for r in self._records:
            prov_dist[r.grant_provider.value] = prov_dist.get(r.grant_provider.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "risk_threshold": self._risk_threshold,
            "provider_distribution": prov_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
