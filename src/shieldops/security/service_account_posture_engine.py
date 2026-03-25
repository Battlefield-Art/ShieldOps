"""Service Account Posture Engine — track service account health and risk posture."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AccountCloud(StrEnum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    KUBERNETES = "kubernetes"
    GITHUB = "github"


class AccountHealth(StrEnum):
    HEALTHY = "healthy"
    AT_RISK = "at_risk"
    STALE = "stale"
    ORPHANED = "orphaned"
    COMPROMISED = "compromised"


class KeyRotationStatus(StrEnum):
    CURRENT = "current"
    DUE = "due"
    OVERDUE = "overdue"
    NEVER_ROTATED = "never_rotated"
    NA = "na"


# --- Models ---


class ServiceAccountPostureRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    account_id: str = ""
    account_cloud: AccountCloud = AccountCloud.AWS
    account_health: AccountHealth = AccountHealth.HEALTHY
    key_rotation_status: KeyRotationStatus = KeyRotationStatus.CURRENT
    days_inactive: int = 0
    permission_count: int = 0
    mfa_enabled: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ServiceAccountPostureAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    account_id: str = ""
    account_cloud: AccountCloud = AccountCloud.AWS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ServiceAccountPostureReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_account_cloud: dict[str, int] = Field(default_factory=dict)
    by_account_health: dict[str, int] = Field(default_factory=dict)
    by_key_rotation_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ServiceAccountPostureEngine:
    """Track service account health, key rotation, and risk posture."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = risk_threshold
        self._records: list[ServiceAccountPostureRecord] = []
        self._analyses: list[ServiceAccountPostureAnalysis] = []
        logger.info(
            "service_account_posture_engine.initialized",
            max_records=max_records,
            risk_threshold=risk_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        account_id: str,
        account_cloud: AccountCloud = AccountCloud.AWS,
        account_health: AccountHealth = AccountHealth.HEALTHY,
        key_rotation_status: KeyRotationStatus = KeyRotationStatus.CURRENT,
        days_inactive: int = 0,
        permission_count: int = 0,
        mfa_enabled: bool = False,
        service: str = "",
        team: str = "",
    ) -> ServiceAccountPostureRecord:
        record = ServiceAccountPostureRecord(
            account_id=account_id,
            account_cloud=account_cloud,
            account_health=account_health,
            key_rotation_status=key_rotation_status,
            days_inactive=days_inactive,
            permission_count=permission_count,
            mfa_enabled=mfa_enabled,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "service_account_posture_engine.record_added",
            record_id=record.id,
            account_id=account_id,
            account_cloud=account_cloud.value,
            account_health=account_health.value,
        )
        return record

    def get_record(self, record_id: str) -> ServiceAccountPostureRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        account_cloud: AccountCloud | None = None,
        account_health: AccountHealth | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ServiceAccountPostureRecord]:
        results = list(self._records)
        if account_cloud is not None:
            results = [r for r in results if r.account_cloud == account_cloud]
        if account_health is not None:
            results = [r for r in results if r.account_health == account_health]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        account_id: str,
        account_cloud: AccountCloud = AccountCloud.AWS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ServiceAccountPostureAnalysis:
        analysis = ServiceAccountPostureAnalysis(
            account_id=account_id,
            account_cloud=account_cloud,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "service_account_posture_engine.analysis_added",
            account_id=account_id,
            account_cloud=account_cloud.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_cloud_distribution(self) -> list[dict[str, Any]]:
        """Analyze service account distribution across cloud providers."""
        cloud_data: dict[str, list[int]] = {}
        for r in self._records:
            cloud_data.setdefault(r.account_cloud.value, []).append(r.permission_count)
        results: list[dict[str, Any]] = []
        for cloud, perms in cloud_data.items():
            unhealthy = sum(
                1
                for r in self._records
                if r.account_cloud.value == cloud and r.account_health != AccountHealth.HEALTHY
            )
            results.append(
                {
                    "account_cloud": cloud,
                    "account_count": len(perms),
                    "avg_permissions": round(sum(perms) / len(perms), 2) if perms else 0.0,
                    "max_permissions": max(perms) if perms else 0,
                    "unhealthy_count": unhealthy,
                }
            )
        return sorted(results, key=lambda x: x["account_count"], reverse=True)

    def identify_at_risk_accounts(self) -> list[dict[str, Any]]:
        """Identify service accounts with elevated risk."""
        at_risk: list[dict[str, Any]] = []
        for r in self._records:
            if r.account_health in (
                AccountHealth.AT_RISK,
                AccountHealth.STALE,
                AccountHealth.ORPHANED,
                AccountHealth.COMPROMISED,
            ):
                risk_score = 0.0
                if r.account_health == AccountHealth.COMPROMISED:
                    risk_score = 100.0
                elif r.account_health == AccountHealth.ORPHANED:
                    risk_score = 80.0
                elif r.account_health == AccountHealth.STALE:
                    risk_score = 60.0
                else:
                    risk_score = 40.0
                if r.key_rotation_status == KeyRotationStatus.NEVER_ROTATED:
                    risk_score = min(100.0, risk_score + 20.0)
                at_risk.append(
                    {
                        "record_id": r.id,
                        "account_id": r.account_id,
                        "account_cloud": r.account_cloud.value,
                        "account_health": r.account_health.value,
                        "key_rotation_status": r.key_rotation_status.value,
                        "days_inactive": r.days_inactive,
                        "permission_count": r.permission_count,
                        "risk_score": risk_score,
                        "service": r.service,
                    }
                )
        return sorted(at_risk, key=lambda x: x["risk_score"], reverse=True)

    def detect_posture_trends(self) -> list[dict[str, Any]]:
        """Detect posture trends across cloud providers."""
        cloud_health: dict[str, dict[str, int]] = {}
        for r in self._records:
            cloud = r.account_cloud.value
            cloud_health.setdefault(cloud, {})
            h = r.account_health.value
            cloud_health[cloud][h] = cloud_health[cloud].get(h, 0) + 1
        results: list[dict[str, Any]] = []
        for cloud, health_map in cloud_health.items():
            total = sum(health_map.values())
            healthy_pct = round(health_map.get("healthy", 0) / total * 100, 2) if total > 0 else 0.0
            results.append(
                {
                    "account_cloud": cloud,
                    "health_distribution": health_map,
                    "total_accounts": total,
                    "healthy_pct": healthy_pct,
                    "at_risk_count": total - health_map.get("healthy", 0),
                }
            )
        return sorted(results, key=lambda x: x["healthy_pct"])

    # -- standard methods ---------------------------------------------------

    def generate_report(self) -> ServiceAccountPostureReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.account_cloud.value] = by_e1.get(r.account_cloud.value, 0) + 1
            by_e2[r.account_health.value] = by_e2.get(r.account_health.value, 0) + 1
            by_e3[r.key_rotation_status.value] = by_e3.get(r.key_rotation_status.value, 0) + 1
        health_scores = {
            AccountHealth.HEALTHY: 100,
            AccountHealth.AT_RISK: 50,
            AccountHealth.STALE: 30,
            AccountHealth.ORPHANED: 20,
            AccountHealth.COMPROMISED: 0,
        }
        scores = [health_scores.get(r.account_health, 50) for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for s in scores if s < self._threshold)
        at_risk = self.identify_at_risk_accounts()
        top_gaps = [o["account_id"] for o in at_risk[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} account(s) below posture threshold ({self._threshold})")
        if avg_score < self._threshold:
            recs.append(f"Avg posture score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Service Account Posture Engine is healthy")
        return ServiceAccountPostureReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_account_cloud=by_e1,
            by_account_health=by_e2,
            by_key_rotation_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("service_account_posture_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.account_cloud.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "risk_threshold": self._threshold,
            "account_cloud_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
