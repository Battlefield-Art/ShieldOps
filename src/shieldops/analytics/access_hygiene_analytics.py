"""Access Hygiene Analytics — permission drift."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class HygieneMetric(StrEnum):
    UNUSED_PERMISSIONS = "unused_permissions"
    STALE_ACCOUNTS = "stale_accounts"
    EXCESSIVE_ROLES = "excessive_roles"
    SHARED_CREDENTIALS = "shared_credentials"
    ORPHANED_ACCESS = "orphaned_access"


class DriftRate(StrEnum):
    NONE = "none"
    SLOW = "slow"
    MODERATE = "moderate"
    RAPID = "rapid"
    CRITICAL = "critical"


class CleanupRate(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    NEGLIGIBLE = "negligible"


# --- Models ---


class AccessHygieneRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    identity_id: str = ""
    metric: HygieneMetric = HygieneMetric.UNUSED_PERMISSIONS
    drift: DriftRate = DriftRate.NONE
    cleanup: CleanupRate = CleanupRate.GOOD
    permission_count: int = 0
    unused_count: int = 0
    days_inactive: int = 0
    created_at: float = Field(default_factory=time.time)


class AccessHygieneAnalysis(BaseModel):
    identity_id: str = ""
    total_permissions: int = 0
    unused_permissions: int = 0
    waste_pct: float = 0.0
    drift_rate: str = ""
    analyzed_at: float = Field(default_factory=time.time)


class AccessHygieneReport(BaseModel):
    total_records: int = 0
    avg_waste_pct: float = 0.0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_drift: dict[str, int] = Field(default_factory=dict)
    high_risk_identities: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AccessHygieneAnalytics:
    """Analyze access hygiene and drift."""

    def __init__(self, max_records: int = 10000) -> None:
        self._max = max_records
        self._records: list[AccessHygieneRecord] = []
        logger.info(
            "access_hygiene_analytics.init",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> AccessHygieneRecord:
        rec = AccessHygieneRecord(**kwargs)
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "access_hygiene.recorded",
            record_id=rec.id,
        )
        return rec

    def process(self, identity_id: str) -> AccessHygieneAnalysis:
        recs = [r for r in self._records if r.identity_id == identity_id]
        if not recs:
            return AccessHygieneAnalysis(identity_id=identity_id)
        total_p = sum(r.permission_count for r in recs)
        unused = sum(r.unused_count for r in recs)
        waste = round(unused / total_p * 100, 2) if total_p else 0.0
        drifts = {
            DriftRate.NONE: 0,
            DriftRate.SLOW: 1,
            DriftRate.MODERATE: 2,
            DriftRate.RAPID: 3,
            DriftRate.CRITICAL: 4,
        }
        max_d = max(recs, key=lambda r: drifts[r.drift])
        return AccessHygieneAnalysis(
            identity_id=identity_id,
            total_permissions=total_p,
            unused_permissions=unused,
            waste_pct=waste,
            drift_rate=max_d.drift.value,
        )

    def generate_report(
        self,
    ) -> AccessHygieneReport:
        by_metric: dict[str, int] = {}
        by_drift: dict[str, int] = {}
        for r in self._records:
            m = r.metric.value
            by_metric[m] = by_metric.get(m, 0) + 1
            d = r.drift.value
            by_drift[d] = by_drift.get(d, 0) + 1
        total = len(self._records)
        wastes: list[float] = []
        for r in self._records:
            if r.permission_count > 0:
                w = r.unused_count / r.permission_count * 100
                wastes.append(w)
        avg_waste = round(sum(wastes) / len(wastes), 2) if wastes else 0.0
        rapid = sum(1 for r in self._records if r.drift in (DriftRate.RAPID, DriftRate.CRITICAL))
        hr_ids = list(
            {
                r.identity_id
                for r in self._records
                if r.drift
                in (
                    DriftRate.RAPID,
                    DriftRate.CRITICAL,
                )
            }
        )[:10]
        recs: list[str] = []
        if avg_waste > 30:
            recs.append(f"Avg waste {avg_waste}% — prune")
        if rapid > 0:
            recs.append(f"{rapid} rapid-drift identity(ies)")
        if not recs:
            recs.append("Access hygiene healthy")
        return AccessHygieneReport(
            total_records=total,
            avg_waste_pct=avg_waste,
            by_metric=by_metric,
            by_drift=by_drift,
            high_risk_identities=hr_ids,
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
        logger.info("access_hygiene_analytics.cleared")

    # -- domain methods --

    def measure_hygiene(
        self,
        identity_id: str | None = None,
    ) -> dict[str, Any]:
        """Measure access hygiene score."""
        recs = self._records
        if identity_id:
            recs = [r for r in recs if r.identity_id == identity_id]
        total_p = sum(r.permission_count for r in recs)
        unused = sum(r.unused_count for r in recs)
        score = round((1 - unused / total_p) * 100, 2) if total_p else 100.0
        return {
            "identity_id": identity_id or "all",
            "total_permissions": total_p,
            "unused_permissions": unused,
            "hygiene_score": score,
        }

    def track_permission_drift(self, window: int = 30) -> list[dict[str, Any]]:
        """Track permission drift over time."""
        by_id: dict[str, list[AccessHygieneRecord]] = {}
        for r in self._records:
            by_id.setdefault(r.identity_id, []).append(r)
        results: list[dict[str, Any]] = []
        for iid, rlist in by_id.items():
            recent = rlist[-window:]
            if len(recent) < 2:
                continue
            first = recent[0].permission_count
            last = recent[-1].permission_count
            delta = last - first
            results.append(
                {
                    "identity_id": iid,
                    "start_perms": first,
                    "end_perms": last,
                    "delta": delta,
                    "growing": delta > 0,
                }
            )
        results.sort(
            key=lambda x: x["delta"],
            reverse=True,
        )
        return results

    def benchmark_vs_policy(
        self,
        max_unused_pct: float = 20.0,
    ) -> dict[str, Any]:
        """Benchmark against policy threshold."""
        compliant = 0
        non_compliant = 0
        for r in self._records:
            if r.permission_count > 0:
                pct = r.unused_count / r.permission_count * 100
                if pct <= max_unused_pct:
                    compliant += 1
                else:
                    non_compliant += 1
        total = compliant + non_compliant
        rate = round(compliant / total * 100, 2) if total else 0.0
        return {
            "threshold_pct": max_unused_pct,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "compliance_rate_pct": rate,
        }
