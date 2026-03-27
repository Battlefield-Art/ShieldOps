"""Asset Lifecycle Engine — lifecycle and decommission."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class LifecyclePhase(StrEnum):
    PROCUREMENT = "procurement"
    DEPLOYMENT = "deployment"
    OPERATIONAL = "operational"
    MAINTENANCE = "maintenance"
    DECOMMISSION = "decommission"


class DecommissionReason(StrEnum):
    END_OF_LIFE = "end_of_life"
    REPLACEMENT = "replacement"
    SECURITY_RISK = "security_risk"
    COST_OPTIMIZATION = "cost_optimization"
    MERGER = "merger"


class ComplianceCheck(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    PENDING = "pending"
    EXEMPT = "exempt"
    NOT_APPLICABLE = "not_applicable"


# --- Models ---


class AssetLifecycleRecord(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    asset_id: str = ""
    asset_name: str = ""
    phase: LifecyclePhase = LifecyclePhase.PROCUREMENT
    decommission_reason: DecommissionReason | None = None
    compliance: ComplianceCheck = ComplianceCheck.PENDING
    owner: str = ""
    environment: str = ""
    created_at: float = Field(default_factory=time.time)


class AssetLifecycleAnalysis(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    asset_id: str = ""
    current_phase: str = ""
    days_in_phase: int = 0
    compliance_status: str = ""
    analyzed_at: float = Field(default_factory=time.time)


class AssetLifecycleReport(BaseModel):
    total_assets: int = 0
    decommission_pending: int = 0
    compliance_failures: int = 0
    by_phase: dict[str, int] = Field(
        default_factory=dict,
    )
    by_compliance: dict[str, int] = Field(
        default_factory=dict,
    )
    recommendations: list[str] = Field(
        default_factory=list,
    )
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AssetLifecycleEngine:
    """Track asset lifecycle and decommission."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[AssetLifecycleRecord] = []
        logger.info(
            "asset_lifecycle.initialized",
            max_records=max_records,
        )

    def _evict(self) -> None:
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]

    def record_item(
        self,
        **kwargs: Any,
    ) -> AssetLifecycleRecord:
        record = AssetLifecycleRecord(**kwargs)
        self._records.append(record)
        self._evict()
        logger.info(
            "asset_lifecycle.item_recorded",
            record_id=record.id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> AssetLifecycleAnalysis:
        matches = [r for r in self._records if r.asset_id == key]
        if not matches:
            return AssetLifecycleAnalysis(
                asset_id=key,
            )
        latest = matches[-1]
        return AssetLifecycleAnalysis(
            asset_id=key,
            current_phase=latest.phase.value,
            compliance_status=latest.compliance.value,
        )

    def generate_report(
        self,
    ) -> AssetLifecycleReport:
        by_phase: dict[str, int] = {}
        by_comp: dict[str, int] = {}
        decom = 0
        failures = 0
        for r in self._records:
            p = r.phase.value
            by_phase[p] = by_phase.get(p, 0) + 1
            c = r.compliance.value
            by_comp[c] = by_comp.get(c, 0) + 1
            if r.phase == LifecyclePhase.DECOMMISSION:
                decom += 1
            if r.compliance == ComplianceCheck.FAILED:
                failures += 1
        recs: list[str] = []
        if decom > 0:
            recs.append(f"{decom} asset(s) pending decommission")
        if failures > 0:
            recs.append(f"{failures} compliance failure(s)")
        if not recs:
            recs.append("Asset lifecycle on track")
        return AssetLifecycleReport(
            total_assets=len(self._records),
            decommission_pending=decom,
            compliance_failures=failures,
            by_phase=by_phase,
            by_compliance=by_comp,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("asset_lifecycle.cleared")
        return {"status": "cleared"}

    # -- domain methods --

    def track_lifecycle(
        self,
        asset_id: str,
        phase: LifecyclePhase,
    ) -> dict[str, Any]:
        """Track lifecycle phase transition."""
        record = self.record_item(
            asset_id=asset_id,
            phase=phase,
        )
        return {
            "record_id": record.id,
            "asset_id": asset_id,
            "phase": phase.value,
        }

    def schedule_decommission(
        self,
        asset_id: str,
        reason: DecommissionReason,
    ) -> dict[str, Any]:
        """Schedule an asset for decommission."""
        record = self.record_item(
            asset_id=asset_id,
            phase=LifecyclePhase.DECOMMISSION,
            decommission_reason=reason,
        )
        return {
            "record_id": record.id,
            "asset_id": asset_id,
            "reason": reason.value,
            "scheduled": True,
        }

    def verify_compliance(
        self,
        asset_id: str,
    ) -> dict[str, Any]:
        """Verify compliance for an asset."""
        matches = [r for r in self._records if r.asset_id == asset_id]
        if not matches:
            return {
                "asset_id": asset_id,
                "found": False,
            }
        latest = matches[-1]
        return {
            "asset_id": asset_id,
            "found": True,
            "compliance": latest.compliance.value,
            "phase": latest.phase.value,
        }
