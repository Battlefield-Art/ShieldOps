"""Entitlement Risk Scorer Engine — score entitlement risk for access reviews."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RiskCategory(StrEnum):
    PRIVILEGE_CREEP = "privilege_creep"
    SEPARATION_OF_DUTIES = "separation_of_duties"
    STALE_ACCESS = "stale_access"
    ORPHANED_ENTITLEMENT = "orphaned_entitlement"
    EXCESSIVE_SCOPE = "excessive_scope"


class IdentityType(StrEnum):
    HUMAN = "human"
    SERVICE_ACCOUNT = "service_account"
    AI_AGENT = "ai_agent"
    GROUP = "group"
    ROLE = "role"


class RiskTrend(StrEnum):
    INCREASING = "increasing"
    STABLE = "stable"
    DECREASING = "decreasing"
    NEW = "new"
    RESOLVED = "resolved"


# --- Models ---


class EntitlementRiskScorerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entitlement_id: str = ""
    risk_category: RiskCategory = RiskCategory.PRIVILEGE_CREEP
    identity_type: IdentityType = IdentityType.HUMAN
    risk_trend: RiskTrend = RiskTrend.STABLE
    risk_score: float = 0.0
    days_since_use: int = 0
    permission_count: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class EntitlementRiskScorerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entitlement_id: str = ""
    risk_category: RiskCategory = RiskCategory.PRIVILEGE_CREEP
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class EntitlementRiskScorerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_risk_category: dict[str, int] = Field(default_factory=dict)
    by_identity_type: dict[str, int] = Field(default_factory=dict)
    by_risk_trend: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class EntitlementRiskScorerEngine:
    """Score entitlement risk for access reviews and identity governance."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = risk_threshold
        self._records: list[EntitlementRiskScorerRecord] = []
        self._analyses: list[EntitlementRiskScorerAnalysis] = []
        logger.info(
            "entitlement_risk_scorer_engine.initialized",
            max_records=max_records,
            risk_threshold=risk_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        entitlement_id: str,
        risk_category: RiskCategory = RiskCategory.PRIVILEGE_CREEP,
        identity_type: IdentityType = IdentityType.HUMAN,
        risk_trend: RiskTrend = RiskTrend.STABLE,
        risk_score: float = 0.0,
        days_since_use: int = 0,
        permission_count: int = 0,
        service: str = "",
        team: str = "",
    ) -> EntitlementRiskScorerRecord:
        record = EntitlementRiskScorerRecord(
            entitlement_id=entitlement_id,
            risk_category=risk_category,
            identity_type=identity_type,
            risk_trend=risk_trend,
            risk_score=risk_score,
            days_since_use=days_since_use,
            permission_count=permission_count,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "entitlement_risk_scorer_engine.record_added",
            record_id=record.id,
            entitlement_id=entitlement_id,
            risk_category=risk_category.value,
            identity_type=identity_type.value,
        )
        return record

    def get_record(self, record_id: str) -> EntitlementRiskScorerRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        risk_category: RiskCategory | None = None,
        identity_type: IdentityType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[EntitlementRiskScorerRecord]:
        results = list(self._records)
        if risk_category is not None:
            results = [r for r in results if r.risk_category == risk_category]
        if identity_type is not None:
            results = [r for r in results if r.identity_type == identity_type]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        entitlement_id: str,
        risk_category: RiskCategory = RiskCategory.PRIVILEGE_CREEP,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> EntitlementRiskScorerAnalysis:
        analysis = EntitlementRiskScorerAnalysis(
            entitlement_id=entitlement_id,
            risk_category=risk_category,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "entitlement_risk_scorer_engine.analysis_added",
            entitlement_id=entitlement_id,
            risk_category=risk_category.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_risk_distribution(self) -> list[dict[str, Any]]:
        """Analyze risk distribution by category and identity type."""
        cat_data: dict[str, list[float]] = {}
        for r in self._records:
            cat_data.setdefault(r.risk_category.value, []).append(r.risk_score)
        results: list[dict[str, Any]] = []
        for cat, scores in cat_data.items():
            avg = round(sum(scores) / len(scores), 2) if scores else 0.0
            above_threshold = sum(1 for s in scores if s >= self._threshold)
            results.append(
                {
                    "risk_category": cat,
                    "count": len(scores),
                    "avg_risk_score": avg,
                    "above_threshold": above_threshold,
                    "max_risk_score": max(scores) if scores else 0.0,
                }
            )
        return sorted(results, key=lambda x: x["avg_risk_score"], reverse=True)

    def identify_highest_risk_entitlements(self) -> list[dict[str, Any]]:
        """Identify entitlements with the highest risk scores."""
        high_risk: list[dict[str, Any]] = []
        for r in self._records:
            if r.risk_score >= self._threshold:
                high_risk.append(
                    {
                        "record_id": r.id,
                        "entitlement_id": r.entitlement_id,
                        "risk_category": r.risk_category.value,
                        "identity_type": r.identity_type.value,
                        "risk_score": r.risk_score,
                        "risk_trend": r.risk_trend.value,
                        "days_since_use": r.days_since_use,
                        "permission_count": r.permission_count,
                        "service": r.service,
                    }
                )
        return sorted(high_risk, key=lambda x: x["risk_score"], reverse=True)

    def detect_risk_trends(self) -> list[dict[str, Any]]:
        """Detect risk trends by identity type."""
        type_trends: dict[str, dict[str, int]] = {}
        for r in self._records:
            it = r.identity_type.value
            type_trends.setdefault(it, {})
            trend = r.risk_trend.value
            type_trends[it][trend] = type_trends[it].get(trend, 0) + 1
        results: list[dict[str, Any]] = []
        for it, trends in type_trends.items():
            total = sum(trends.values())
            increasing_pct = (
                round(trends.get("increasing", 0) / total * 100, 2) if total > 0 else 0.0
            )
            results.append(
                {
                    "identity_type": it,
                    "trend_distribution": trends,
                    "total_entitlements": total,
                    "increasing_pct": increasing_pct,
                    "resolved_count": trends.get("resolved", 0),
                }
            )
        return sorted(results, key=lambda x: x["increasing_pct"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def generate_report(self) -> EntitlementRiskScorerReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.risk_category.value] = by_e1.get(r.risk_category.value, 0) + 1
            by_e2[r.identity_type.value] = by_e2.get(r.identity_type.value, 0) + 1
            by_e3[r.risk_trend.value] = by_e3.get(r.risk_trend.value, 0) + 1
        scores = [r.risk_score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        high_risk = self.identify_highest_risk_entitlements()
        gap_count = len(high_risk)
        top_gaps = [o["entitlement_id"] for o in high_risk[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} entitlement(s) above risk threshold ({self._threshold})")
        if avg_score >= self._threshold:
            recs.append(f"Avg risk score {avg_score} at or above threshold ({self._threshold})")
        if not recs:
            recs.append("Entitlement Risk Scorer Engine is healthy")
        return EntitlementRiskScorerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_risk_category=by_e1,
            by_identity_type=by_e2,
            by_risk_trend=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("entitlement_risk_scorer_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.risk_category.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "risk_threshold": self._threshold,
            "risk_category_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
