"""IT Asset Risk Engine — asset risk and patch tracking."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AssetLifecycle(StrEnum):
    PROVISIONED = "provisioned"
    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    DEPRECATED = "deprecated"
    DECOMMISSIONED = "decommissioned"


class PatchCompliance(StrEnum):
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"
    EXEMPT = "exempt"


class ConfigDrift(StrEnum):
    NONE = "none"
    MINOR = "minor"
    MODERATE = "moderate"
    SEVERE = "severe"
    CRITICAL = "critical"


# --- Models ---


class ITAssetRiskRecord(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    asset_id: str = ""
    asset_name: str = ""
    lifecycle: AssetLifecycle = AssetLifecycle.ACTIVE
    patch_status: PatchCompliance = PatchCompliance.UNKNOWN
    drift_level: ConfigDrift = ConfigDrift.NONE
    risk_score: float = 0.0
    owner: str = ""
    environment: str = ""
    created_at: float = Field(default_factory=time.time)


class ITAssetRiskAnalysis(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    asset_id: str = ""
    risk_factors: list[str] = Field(
        default_factory=list,
    )
    patch_gap_days: int = 0
    drift_details: str = ""
    remediation_priority: int = 0
    analyzed_at: float = Field(default_factory=time.time)


class ITAssetRiskReport(BaseModel):
    total_assets: int = 0
    high_risk_count: int = 0
    non_compliant_count: int = 0
    drift_count: int = 0
    by_lifecycle: dict[str, int] = Field(
        default_factory=dict,
    )
    by_patch_status: dict[str, int] = Field(
        default_factory=dict,
    )
    recommendations: list[str] = Field(
        default_factory=list,
    )
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ITAssetRiskEngine:
    """Assess IT asset risk, patches, and drift."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 0.7,
    ) -> None:
        self._max_records = max_records
        self._risk_threshold = risk_threshold
        self._records: list[ITAssetRiskRecord] = []
        logger.info(
            "it_asset_risk.initialized",
            max_records=max_records,
        )

    def _evict(self) -> None:
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]

    def add_record(self, **kwargs: Any) -> ITAssetRiskRecord:
        record = ITAssetRiskRecord(**kwargs)
        self._records.append(record)
        self._evict()
        logger.info(
            "it_asset_risk.record_added",
            record_id=record.id,
            asset_id=record.asset_id,
        )
        return record

    def process(self, key: str) -> ITAssetRiskAnalysis:
        matches = [r for r in self._records if r.asset_id == key]
        if not matches:
            return ITAssetRiskAnalysis(asset_id=key)
        latest = matches[-1]
        factors: list[str] = []
        if latest.patch_status == PatchCompliance.NON_COMPLIANT:
            factors.append("non_compliant_patches")
        if latest.drift_level in (
            ConfigDrift.SEVERE,
            ConfigDrift.CRITICAL,
        ):
            factors.append("severe_config_drift")
        if latest.lifecycle == AssetLifecycle.DEPRECATED:
            factors.append("deprecated_asset")
        return ITAssetRiskAnalysis(
            asset_id=key,
            risk_factors=factors,
            remediation_priority=len(factors),
        )

    def generate_report(self) -> ITAssetRiskReport:
        by_lifecycle: dict[str, int] = {}
        by_patch: dict[str, int] = {}
        high_risk = 0
        non_compliant = 0
        drift_count = 0
        for r in self._records:
            lc = r.lifecycle.value
            by_lifecycle[lc] = by_lifecycle.get(lc, 0) + 1
            ps = r.patch_status.value
            by_patch[ps] = by_patch.get(ps, 0) + 1
            if r.risk_score >= self._risk_threshold:
                high_risk += 1
            if r.patch_status == PatchCompliance.NON_COMPLIANT:
                non_compliant += 1
            if r.drift_level != ConfigDrift.NONE:
                drift_count += 1
        recs: list[str] = []
        if high_risk > 0:
            recs.append(f"{high_risk} high-risk asset(s) found")
        if non_compliant > 0:
            recs.append(f"{non_compliant} non-compliant asset(s)")
        if drift_count > 0:
            recs.append(f"{drift_count} asset(s) with config drift")
        if not recs:
            recs.append("All assets within tolerance")
        return ITAssetRiskReport(
            total_assets=len(self._records),
            high_risk_count=high_risk,
            non_compliant_count=non_compliant,
            drift_count=drift_count,
            by_lifecycle=by_lifecycle,
            by_patch_status=by_patch,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "risk_threshold": self._risk_threshold,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("it_asset_risk.cleared")
        return {"status": "cleared"}

    # -- domain methods --

    def assess_asset_risk(
        self,
        asset_id: str,
    ) -> dict[str, Any]:
        """Compute composite risk for an asset."""
        matches = [r for r in self._records if r.asset_id == asset_id]
        if not matches:
            return {"asset_id": asset_id, "found": False}
        latest = matches[-1]
        score = latest.risk_score
        if latest.patch_status == PatchCompliance.NON_COMPLIANT:
            score = min(score + 0.2, 1.0)
        if latest.drift_level in (
            ConfigDrift.SEVERE,
            ConfigDrift.CRITICAL,
        ):
            score = min(score + 0.15, 1.0)
        return {
            "asset_id": asset_id,
            "found": True,
            "risk_score": round(score, 4),
            "lifecycle": latest.lifecycle.value,
        }

    def track_patch_status(
        self,
        asset_id: str,
        status: PatchCompliance,
    ) -> dict[str, Any]:
        """Update patch compliance for an asset."""
        matches = [r for r in self._records if r.asset_id == asset_id]
        if not matches:
            return {"asset_id": asset_id, "updated": False}
        latest = matches[-1]
        previous = latest.patch_status.value
        latest.patch_status = status
        logger.info(
            "it_asset_risk.patch_updated",
            asset_id=asset_id,
            previous=previous,
            new=status.value,
        )
        return {
            "asset_id": asset_id,
            "updated": True,
            "previous": previous,
            "current": status.value,
        }

    def detect_config_drift(
        self,
        asset_id: str,
    ) -> dict[str, Any]:
        """Detect config drift for an asset."""
        matches = [r for r in self._records if r.asset_id == asset_id]
        if not matches:
            return {"asset_id": asset_id, "found": False}
        latest = matches[-1]
        return {
            "asset_id": asset_id,
            "found": True,
            "drift_level": latest.drift_level.value,
            "is_drifted": (latest.drift_level != ConfigDrift.NONE),
        }
