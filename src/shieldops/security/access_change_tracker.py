"""Access Change Tracker — track access changes."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ChangeScope(StrEnum):
    USER = "user"
    GROUP = "group"
    ROLE = "role"
    SERVICE_ACCOUNT = "service_account"
    POLICY = "policy"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    AUTO_APPROVED = "auto_approved"
    EXPIRED = "expired"


class ImpactLevel(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --- Models ---


class AccessChangeRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    identity_id: str = ""
    scope: ChangeScope = ChangeScope.USER
    approval: ApprovalStatus = ApprovalStatus.PENDING
    impact: ImpactLevel = ImpactLevel.LOW
    change_type: str = ""
    before_state: str = ""
    after_state: str = ""
    created_at: float = Field(default_factory=time.time)


class AccessChangeAnalysis(BaseModel):
    identity_id: str = ""
    total_changes: int = 0
    approved_count: int = 0
    denied_count: int = 0
    high_impact_count: int = 0
    avg_impact: str = ""
    analyzed_at: float = Field(default_factory=time.time)


class AccessChangeReport(BaseModel):
    total_changes: int = 0
    approval_rate_pct: float = 0.0
    by_scope: dict[str, int] = Field(default_factory=dict)
    by_impact: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AccessChangeTracker:
    """Track access permission changes."""

    def __init__(self, max_records: int = 10000) -> None:
        self._max = max_records
        self._records: list[AccessChangeRecord] = []
        logger.info(
            "access_change_tracker.init",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> AccessChangeRecord:
        rec = AccessChangeRecord(**kwargs)
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "access_change_tracker.recorded",
            record_id=rec.id,
        )
        return rec

    def process(self, identity_id: str) -> AccessChangeAnalysis:
        recs = [r for r in self._records if r.identity_id == identity_id]
        if not recs:
            return AccessChangeAnalysis(identity_id=identity_id)
        approved = sum(
            1
            for r in recs
            if r.approval
            in (
                ApprovalStatus.APPROVED,
                ApprovalStatus.AUTO_APPROVED,
            )
        )
        denied = sum(1 for r in recs if r.approval == ApprovalStatus.DENIED)
        high = sum(1 for r in recs if r.impact in (ImpactLevel.HIGH, ImpactLevel.CRITICAL))
        impacts = {
            ImpactLevel.NONE: 0,
            ImpactLevel.LOW: 1,
            ImpactLevel.MEDIUM: 2,
            ImpactLevel.HIGH: 3,
            ImpactLevel.CRITICAL: 4,
        }
        vals = [impacts[r.impact] for r in recs]
        avg_v = sum(vals) / len(vals) if vals else 0
        avg_label = "low"
        if avg_v >= 3:
            avg_label = "high"
        elif avg_v >= 2:
            avg_label = "medium"
        return AccessChangeAnalysis(
            identity_id=identity_id,
            total_changes=len(recs),
            approved_count=approved,
            denied_count=denied,
            high_impact_count=high,
            avg_impact=avg_label,
        )

    def generate_report(self) -> AccessChangeReport:
        by_scope: dict[str, int] = {}
        by_impact: dict[str, int] = {}
        for r in self._records:
            s = r.scope.value
            by_scope[s] = by_scope.get(s, 0) + 1
            i = r.impact.value
            by_impact[i] = by_impact.get(i, 0) + 1
        total = len(self._records)
        approved = sum(
            1
            for r in self._records
            if r.approval
            in (
                ApprovalStatus.APPROVED,
                ApprovalStatus.AUTO_APPROVED,
            )
        )
        rate = round(approved / total * 100, 2) if total else 0.0
        recs: list[str] = []
        high = by_impact.get("high", 0) + by_impact.get("critical", 0)
        if high > 0:
            recs.append(f"{high} high-impact change(s)")
        denied = sum(1 for r in self._records if r.approval == ApprovalStatus.DENIED)
        if denied > 0:
            recs.append(f"{denied} change(s) denied")
        if not recs:
            recs.append("Access changes nominal")
        return AccessChangeReport(
            total_changes=total,
            approval_rate_pct=rate,
            by_scope=by_scope,
            by_impact=by_impact,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max,
            "unique_identities": len({r.identity_id for r in self._records}),
        }

    def clear_data(self) -> None:
        self._records.clear()
        logger.info("access_change_tracker.cleared")

    # -- domain methods --

    def track_change(
        self,
        identity_id: str,
        scope: ChangeScope,
        impact: ImpactLevel,
        change_type: str = "",
        before_state: str = "",
        after_state: str = "",
    ) -> AccessChangeRecord:
        """Record an access change event."""
        return self.add_record(
            identity_id=identity_id,
            scope=scope,
            impact=impact,
            change_type=change_type,
            before_state=before_state,
            after_state=after_state,
        )

    def measure_access_reduction(
        self,
    ) -> dict[str, Any]:
        """Measure net access reduction."""
        grants = sum(1 for r in self._records if r.change_type == "grant")
        revokes = sum(1 for r in self._records if r.change_type == "revoke")
        net = revokes - grants
        return {
            "grants": grants,
            "revokes": revokes,
            "net_reduction": net,
            "reducing": net > 0,
        }

    def audit_change_history(
        self,
        identity_id: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return change history for an identity."""
        recs = [r for r in self._records if r.identity_id == identity_id]
        return [
            {
                "id": r.id,
                "scope": r.scope.value,
                "impact": r.impact.value,
                "approval": r.approval.value,
                "change_type": r.change_type,
                "created_at": r.created_at,
            }
            for r in recs[-limit:]
        ]
