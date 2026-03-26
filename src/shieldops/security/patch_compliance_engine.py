"""Patch Compliance Engine —
track patch deployment across assets,
measure compliance rates, manage deferral policies."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PatchSource(StrEnum):
    VENDOR = "vendor"
    COMMUNITY = "community"
    INTERNAL = "internal"
    BACKPORT = "backport"
    WORKAROUND = "workaround"


class ComplianceState(StrEnum):
    PATCHED = "patched"
    UNPATCHED = "unpatched"
    PARTIAL = "partial"
    DEFERRED = "deferred"
    EXEMPT = "exempt"


class AssetCriticality(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    DEV_ONLY = "dev_only"


# --- Models ---


class PatchComplianceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    patch_id: str = ""
    asset_name: str = ""
    patch_source: PatchSource = PatchSource.VENDOR
    compliance_state: ComplianceState = ComplianceState.UNPATCHED
    asset_criticality: AssetCriticality = AssetCriticality.MEDIUM
    cve_ids: list[str] = Field(default_factory=list)
    days_since_release: float = 0.0
    deployment_attempts: int = 0
    rollback_count: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PatchComplianceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    asset_name: str = ""
    compliance_state: ComplianceState = ComplianceState.UNPATCHED
    compliance_pct: float = 0.0
    unpatched_critical: int = 0
    risk_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PatchComplianceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    overall_compliance_pct: float = 0.0
    by_patch_source: dict[str, int] = Field(default_factory=dict)
    by_compliance_state: dict[str, int] = Field(default_factory=dict)
    by_asset_criticality: dict[str, int] = Field(default_factory=dict)
    non_compliant_assets: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class PatchComplianceEngine:
    """Track patch deployment across assets,
    measure compliance rates, manage deferral policies."""

    def __init__(self, max_records: int = 200000, compliance_threshold: float = 90.0) -> None:
        self._max_records = max_records
        self._compliance_threshold = compliance_threshold
        self._records: list[PatchComplianceRecord] = []
        self._analyses: dict[str, PatchComplianceAnalysis] = {}
        logger.info(
            "patch_compliance_engine.init",
            max_records=max_records,
            compliance_threshold=compliance_threshold,
        )

    def add_record(
        self,
        patch_id: str = "",
        asset_name: str = "",
        patch_source: PatchSource = PatchSource.VENDOR,
        compliance_state: ComplianceState = ComplianceState.UNPATCHED,
        asset_criticality: AssetCriticality = AssetCriticality.MEDIUM,
        cve_ids: list[str] | None = None,
        days_since_release: float = 0.0,
        deployment_attempts: int = 0,
        rollback_count: int = 0,
        description: str = "",
    ) -> PatchComplianceRecord:
        record = PatchComplianceRecord(
            patch_id=patch_id,
            asset_name=asset_name,
            patch_source=patch_source,
            compliance_state=compliance_state,
            asset_criticality=asset_criticality,
            cve_ids=cve_ids or [],
            days_since_release=days_since_release,
            deployment_attempts=deployment_attempts,
            rollback_count=rollback_count,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "patch_compliance.record_added",
            record_id=record.id,
            patch_id=patch_id,
        )
        return record

    def process(self, key: str) -> PatchComplianceAnalysis | dict[str, Any]:
        recs = [r for r in self._records if r.asset_name == key or r.id == key]
        if not recs:
            return {"status": "not_found", "key": key}
        patched = sum(1 for r in recs if r.compliance_state == ComplianceState.PATCHED)
        compliance_pct = round(patched / len(recs) * 100, 2)
        unpatched_crit = sum(
            1
            for r in recs
            if r.compliance_state == ComplianceState.UNPATCHED
            and r.asset_criticality in (AssetCriticality.CRITICAL, AssetCriticality.HIGH)
        )
        risk = round((100 - compliance_pct) + unpatched_crit * 15, 2)
        analysis = PatchComplianceAnalysis(
            asset_name=recs[0].asset_name,
            compliance_state=recs[0].compliance_state,
            compliance_pct=compliance_pct,
            unpatched_critical=unpatched_crit,
            risk_score=risk,
            description=(
                f"{recs[0].asset_name} compliance={compliance_pct}% "
                f"unpatched_critical={unpatched_crit} risk={risk}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> PatchComplianceReport:
        by_source: dict[str, int] = {}
        by_state: dict[str, int] = {}
        by_crit: dict[str, int] = {}
        for r in self._records:
            ps = r.patch_source.value
            by_source[ps] = by_source.get(ps, 0) + 1
            cs = r.compliance_state.value
            by_state[cs] = by_state.get(cs, 0) + 1
            ac = r.asset_criticality.value
            by_crit[ac] = by_crit.get(ac, 0) + 1
        patched = by_state.get("patched", 0)
        total = len(self._records)
        overall_pct = round(patched / total * 100, 2) if total else 0.0
        non_compliant = list(
            {
                r.asset_name
                for r in self._records
                if r.compliance_state == ComplianceState.UNPATCHED
                and r.asset_criticality in (AssetCriticality.CRITICAL, AssetCriticality.HIGH)
            }
        )[:10]
        recs: list[str] = []
        if overall_pct < self._compliance_threshold:
            recs.append(
                f"Overall compliance {overall_pct}% below {self._compliance_threshold}% target"
            )
        if non_compliant:
            recs.append(f"{len(non_compliant)} critical/high assets unpatched")
        if not recs:
            recs.append("Patch compliance within acceptable thresholds")
        return PatchComplianceReport(
            total_records=total,
            total_analyses=len(self._analyses),
            overall_compliance_pct=overall_pct,
            by_patch_source=by_source,
            by_compliance_state=by_state,
            by_asset_criticality=by_crit,
            non_compliant_assets=non_compliant,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        state_dist: dict[str, int] = {}
        for r in self._records:
            k = r.compliance_state.value
            state_dist[k] = state_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "state_distribution": state_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("patch_compliance_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def find_overdue_patches(self) -> list[dict[str, Any]]:
        """Find patches that are overdue based on days since release."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.compliance_state == ComplianceState.UNPATCHED and r.days_since_release > 14:
                results.append(
                    {
                        "patch_id": r.patch_id,
                        "asset_name": r.asset_name,
                        "asset_criticality": r.asset_criticality.value,
                        "days_since_release": r.days_since_release,
                        "cve_count": len(r.cve_ids),
                        "deployment_attempts": r.deployment_attempts,
                    }
                )
        results.sort(key=lambda x: x["days_since_release"], reverse=True)
        return results

    def analyze_rollback_rates(self) -> list[dict[str, Any]]:
        """Analyze patch rollback rates by source."""
        source_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            ps = r.patch_source.value
            source_data.setdefault(ps, {"total": 0, "rollbacks": 0})
            source_data[ps]["total"] += 1
            source_data[ps]["rollbacks"] += r.rollback_count
        results: list[dict[str, Any]] = []
        for source, data in source_data.items():
            rollback_rate = (
                round(data["rollbacks"] / data["total"] * 100, 2) if data["total"] > 0 else 0.0
            )
            results.append(
                {
                    "patch_source": source,
                    "total_patches": data["total"],
                    "total_rollbacks": data["rollbacks"],
                    "rollback_rate_pct": rollback_rate,
                }
            )
        results.sort(key=lambda x: x["rollback_rate_pct"], reverse=True)
        return results

    def rank_assets_by_compliance(self) -> list[dict[str, Any]]:
        """Rank assets by patch compliance rate."""
        asset_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            a = r.asset_name
            asset_data.setdefault(a, {"total": 0, "patched": 0})
            asset_data[a]["total"] += 1
            if r.compliance_state == ComplianceState.PATCHED:
                asset_data[a]["patched"] += 1
        results: list[dict[str, Any]] = []
        for asset, data in asset_data.items():
            pct = round(data["patched"] / data["total"] * 100, 2) if data["total"] > 0 else 0.0
            results.append(
                {
                    "asset_name": asset,
                    "total_patches": data["total"],
                    "patched": data["patched"],
                    "compliance_pct": pct,
                    "rank": 0,
                }
            )
        results.sort(key=lambda x: x["compliance_pct"])
        for idx, entry in enumerate(results, 1):
            entry["rank"] = idx
        return results
