"""Patch Compliance Analytics — patch posture."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ComplianceWindow(StrEnum):
    WITHIN_SLA = "within_sla"
    APPROACHING = "approaching"
    OVERDUE = "overdue"
    CRITICAL_OVERDUE = "critical_overdue"
    EXEMPT = "exempt"


class PatchAge(StrEnum):
    CURRENT = "current"
    RECENT = "recent"
    STALE = "stale"
    OUTDATED = "outdated"
    ANCIENT = "ancient"


class RiskExposure(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --- Models ---


class PatchComplianceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str = ""
    patch_id: str = ""
    window: ComplianceWindow = ComplianceWindow.WITHIN_SLA
    age: PatchAge = PatchAge.CURRENT
    exposure: RiskExposure = RiskExposure.NONE
    days_since_release: int = 0
    applied: bool = False
    created_at: float = Field(default_factory=time.time)


class PatchComplianceAnalysis(BaseModel):
    asset_id: str = ""
    total_patches: int = 0
    applied_count: int = 0
    overdue_count: int = 0
    compliance_pct: float = 0.0
    max_exposure: str = ""
    analyzed_at: float = Field(default_factory=time.time)


class PatchComplianceReport(BaseModel):
    total_records: int = 0
    overall_compliance_pct: float = 0.0
    by_window: dict[str, int] = Field(default_factory=dict)
    by_exposure: dict[str, int] = Field(default_factory=dict)
    overdue_assets: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class PatchComplianceAnalytics:
    """Analyze patch compliance posture."""

    def __init__(self, max_records: int = 10000) -> None:
        self._max = max_records
        self._records: list[PatchComplianceRecord] = []
        logger.info(
            "patch_compliance_analytics.init",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> PatchComplianceRecord:
        rec = PatchComplianceRecord(**kwargs)
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "patch_compliance.recorded",
            record_id=rec.id,
        )
        return rec

    def process(self, asset_id: str) -> PatchComplianceAnalysis:
        recs = [r for r in self._records if r.asset_id == asset_id]
        if not recs:
            return PatchComplianceAnalysis(asset_id=asset_id)
        applied = sum(1 for r in recs if r.applied)
        overdue = sum(
            1
            for r in recs
            if r.window
            in (
                ComplianceWindow.OVERDUE,
                ComplianceWindow.CRITICAL_OVERDUE,
            )
        )
        rate = round(applied / len(recs) * 100, 2)
        exposures = {
            RiskExposure.NONE: 0,
            RiskExposure.LOW: 1,
            RiskExposure.MEDIUM: 2,
            RiskExposure.HIGH: 3,
            RiskExposure.CRITICAL: 4,
        }
        max_exp = max(recs, key=lambda r: exposures[r.exposure])
        return PatchComplianceAnalysis(
            asset_id=asset_id,
            total_patches=len(recs),
            applied_count=applied,
            overdue_count=overdue,
            compliance_pct=rate,
            max_exposure=max_exp.exposure.value,
        )

    def generate_report(
        self,
    ) -> PatchComplianceReport:
        by_win: dict[str, int] = {}
        by_exp: dict[str, int] = {}
        for r in self._records:
            w = r.window.value
            by_win[w] = by_win.get(w, 0) + 1
            e = r.exposure.value
            by_exp[e] = by_exp.get(e, 0) + 1
        total = len(self._records)
        applied = sum(1 for r in self._records if r.applied)
        rate = round(applied / total * 100, 2) if total else 0.0
        overdue_assets = len(
            {
                r.asset_id
                for r in self._records
                if r.window
                in (
                    ComplianceWindow.OVERDUE,
                    ComplianceWindow.CRITICAL_OVERDUE,
                )
            }
        )
        recs: list[str] = []
        if overdue_assets > 0:
            recs.append(f"{overdue_assets} asset(s) overdue")
        crit = by_exp.get("critical", 0)
        if crit > 0:
            recs.append(f"{crit} critical exposure(s)")
        if not recs:
            recs.append("Patch compliance on track")
        return PatchComplianceReport(
            total_records=total,
            overall_compliance_pct=rate,
            by_window=by_win,
            by_exposure=by_exp,
            overdue_assets=overdue_assets,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max,
            "unique_assets": len({r.asset_id for r in self._records}),
        }

    def clear_data(self) -> None:
        self._records.clear()
        logger.info("patch_compliance_analytics.cleared")

    # -- domain methods --

    def measure_compliance_rate(self, asset_id: str | None = None) -> dict[str, Any]:
        """Measure patch compliance rate."""
        recs = self._records
        if asset_id:
            recs = [r for r in recs if r.asset_id == asset_id]
        total = len(recs)
        applied = sum(1 for r in recs if r.applied)
        rate = round(applied / total * 100, 2) if total else 0.0
        return {
            "asset_id": asset_id or "all",
            "total": total,
            "applied": applied,
            "compliance_pct": rate,
        }

    def track_exposure_window(
        self,
    ) -> list[dict[str, Any]]:
        """Track risk exposure windows."""
        by_asset: dict[str, list[int]] = {}
        for r in self._records:
            if not r.applied:
                by_asset.setdefault(r.asset_id, []).append(r.days_since_release)
        return [
            {
                "asset_id": aid,
                "unpatched_count": len(days),
                "max_days": max(days),
                "avg_days": round(sum(days) / len(days), 1),
            }
            for aid, days in sorted(
                by_asset.items(),
                key=lambda x: max(x[1]),
                reverse=True,
            )
        ]

    def forecast_risk(self, days_ahead: int = 30) -> dict[str, Any]:
        """Forecast risk based on patch age."""
        approaching = sum(
            1 for r in self._records if not r.applied and r.days_since_release + days_ahead > 90
        )
        total_unpatched = sum(1 for r in self._records if not r.applied)
        return {
            "days_ahead": days_ahead,
            "total_unpatched": total_unpatched,
            "will_become_overdue": approaching,
            "risk_level": (
                "critical" if approaching > 10 else "medium" if approaching > 3 else "low"
            ),
        }
