"""Service Account Tracker — track and risk-assess machine identities."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AccountType(StrEnum):
    KUBERNETES_SA = "kubernetes_sa"
    CLOUD_IAM = "cloud_iam"
    DATABASE = "database"
    CI_CD = "ci_cd"
    MONITORING = "monitoring"
    API_GATEWAY = "api_gateway"


class AccountRisk(StrEnum):
    MINIMAL = "minimal"
    STANDARD = "standard"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"


class AccountStatus(StrEnum):
    ACTIVE = "active"
    DORMANT = "dormant"
    ORPHANED = "orphaned"
    COMPROMISED = "compromised"
    DECOMMISSIONED = "decommissioned"


# --- Models ---


class ServiceAccountRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    account_name: str = ""
    account_type: AccountType = AccountType.CLOUD_IAM
    account_risk: AccountRisk = AccountRisk.STANDARD
    account_status: AccountStatus = AccountStatus.ACTIVE
    owner_team: str = ""
    permissions: list[str] = Field(default_factory=list)
    last_authenticated_at: float = 0.0
    created_at: float = Field(default_factory=time.time)


class AccountActivity(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    account_id: str = ""
    action: str = ""
    resource_accessed: str = ""
    source_ip: str = ""
    is_anomalous: bool = False
    recorded_at: float = Field(default_factory=time.time)


class ServiceAccountReport(BaseModel):
    total_accounts: int = 0
    dormant_count: int = 0
    orphaned_count: int = 0
    high_risk_count: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_risk: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---

_DORMANT_DAYS = 60
_HIGH_PERMISSION_THRESHOLD = 10


class ServiceAccountTracker:
    """Track and risk-assess machine identities."""

    def __init__(self, max_records: int = 200000, dormant_days: int = 60) -> None:
        self._max_records = max_records
        self._dormant_days = dormant_days
        self._records: list[ServiceAccountRecord] = []
        self._activities: list[AccountActivity] = []
        logger.info(
            "service_account_tracker.initialized",
            max_records=max_records,
            dormant_days=dormant_days,
        )

    # -- record / get --------------------------------------------------------

    def register_account(
        self,
        account_name: str,
        account_type: AccountType = AccountType.CLOUD_IAM,
        owner_team: str = "",
        permissions: list[str] | None = None,
        last_authenticated_at: float = 0.0,
    ) -> ServiceAccountRecord:
        record = ServiceAccountRecord(
            account_name=account_name,
            account_type=account_type,
            owner_team=owner_team,
            permissions=permissions or [],
            last_authenticated_at=last_authenticated_at,
        )
        record.account_risk = self._compute_risk(record)
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "service_account_tracker.account_registered",
            record_id=record.id,
            account_name=account_name,
            account_type=account_type.value,
        )
        return record

    def record_activity(
        self,
        account_id: str,
        action: str,
        resource_accessed: str = "",
        source_ip: str = "",
        is_anomalous: bool = False,
    ) -> AccountActivity:
        activity = AccountActivity(
            account_id=account_id,
            action=action,
            resource_accessed=resource_accessed,
            source_ip=source_ip,
            is_anomalous=is_anomalous,
        )
        self._activities.append(activity)
        if len(self._activities) > self._max_records:
            self._activities = self._activities[-self._max_records :]
        # Update last_authenticated_at for the account
        for r in self._records:
            if r.id == account_id:
                r.last_authenticated_at = time.time()
                break
        logger.info(
            "service_account_tracker.activity_recorded",
            account_id=account_id,
            action=action,
            is_anomalous=is_anomalous,
        )
        return activity

    # -- domain operations ---------------------------------------------------

    def detect_dormant_accounts(self) -> list[dict[str, Any]]:
        """Find accounts that have not authenticated within dormant threshold."""
        now = time.time()
        threshold = self._dormant_days * 86400
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.account_status == AccountStatus.DECOMMISSIONED:
                continue
            last_auth = r.last_authenticated_at or r.created_at
            if (now - last_auth) > threshold:
                days_dormant = int((now - last_auth) / 86400)
                results.append(
                    {
                        "account_id": r.id,
                        "account_name": r.account_name,
                        "account_type": r.account_type.value,
                        "days_dormant": days_dormant,
                        "permissions_count": len(r.permissions),
                        "owner_team": r.owner_team,
                    }
                )
        results.sort(key=lambda x: x["days_dormant"], reverse=True)
        return results

    def detect_orphaned_accounts(self) -> list[dict[str, Any]]:
        """Find accounts with no owner team or whose owner team is unknown."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.account_status == AccountStatus.DECOMMISSIONED:
                continue
            if not r.owner_team or r.owner_team.lower() in ("unknown", "none", ""):
                results.append(
                    {
                        "account_id": r.id,
                        "account_name": r.account_name,
                        "account_type": r.account_type.value,
                        "permissions_count": len(r.permissions),
                        "risk": r.account_risk.value,
                    }
                )
        return results

    def assess_privilege_creep(self) -> list[dict[str, Any]]:
        """Identify accounts with permissions exceeding threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if len(r.permissions) > _HIGH_PERMISSION_THRESHOLD:
                results.append(
                    {
                        "account_id": r.id,
                        "account_name": r.account_name,
                        "account_type": r.account_type.value,
                        "permissions_count": len(r.permissions),
                        "excess_permissions": len(r.permissions) - _HIGH_PERMISSION_THRESHOLD,
                        "permissions": r.permissions[:20],
                        "risk": r.account_risk.value,
                    }
                )
        results.sort(key=lambda x: x["permissions_count"], reverse=True)
        return results

    # -- report / stats ------------------------------------------------------

    def generate_account_report(self) -> ServiceAccountReport:
        by_type: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for r in self._records:
            by_type[r.account_type.value] = by_type.get(r.account_type.value, 0) + 1
            by_risk[r.account_risk.value] = by_risk.get(r.account_risk.value, 0) + 1
            by_status[r.account_status.value] = by_status.get(r.account_status.value, 0) + 1

        dormant = self.detect_dormant_accounts()
        orphaned = self.detect_orphaned_accounts()
        high_risk = sum(
            1 for r in self._records if r.account_risk in (AccountRisk.HIGH, AccountRisk.CRITICAL)
        )

        recs: list[str] = []
        if dormant:
            recs.append(f"{len(dormant)} dormant account(s) — review for decommission")
        if orphaned:
            recs.append(f"{len(orphaned)} orphaned account(s) — assign owners")
        creep = self.assess_privilege_creep()
        if creep:
            recs.append(f"{len(creep)} account(s) with privilege creep — reduce permissions")
        if not recs:
            recs.append("Service account hygiene meets targets")

        return ServiceAccountReport(
            total_accounts=len(self._records),
            dormant_count=len(dormant),
            orphaned_count=len(orphaned),
            high_risk_count=high_risk,
            by_type=by_type,
            by_risk=by_risk,
            by_status=by_status,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            type_dist[r.account_type.value] = type_dist.get(r.account_type.value, 0) + 1
        return {
            "total_accounts": len(self._records),
            "total_activities": len(self._activities),
            "dormant_days_threshold": self._dormant_days,
            "type_distribution": type_dist,
            "anomalous_activities": sum(1 for a in self._activities if a.is_anomalous),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._activities.clear()
        logger.info("service_account_tracker.cleared")
        return {"status": "cleared"}

    # -- private helpers -----------------------------------------------------

    @staticmethod
    def _compute_risk(record: ServiceAccountRecord) -> AccountRisk:
        perm_count = len(record.permissions)
        if perm_count > 20:
            return AccountRisk.CRITICAL
        if perm_count > _HIGH_PERMISSION_THRESHOLD:
            return AccountRisk.HIGH
        if perm_count > 5:
            return AccountRisk.ELEVATED
        if perm_count > 2:
            return AccountRisk.STANDARD
        return AccountRisk.MINIMAL
