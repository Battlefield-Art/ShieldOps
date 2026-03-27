"""Backup Hardening Engine — controls and risk."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class HardeningControl(StrEnum):
    ENCRYPTION_AT_REST = "encryption_at_rest"
    IMMUTABLE_BACKUPS = "immutable_backups"
    AIR_GAP = "air_gap"
    MFA_DELETE = "mfa_delete"
    ACCESS_LOGGING = "access_logging"


class ImplementationStatus(StrEnum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"
    FAILED = "failed"


class RiskReduction(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --- Models ---


class BackupHardeningRecord(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    backup_target: str = ""
    control: HardeningControl = HardeningControl.ENCRYPTION_AT_REST
    status: ImplementationStatus = ImplementationStatus.NOT_STARTED
    risk_reduction: RiskReduction = RiskReduction.NONE
    environment: str = ""
    notes: str = ""
    created_at: float = Field(default_factory=time.time)


class BackupHardeningAnalysis(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    backup_target: str = ""
    controls_implemented: int = 0
    controls_total: int = 0
    coverage_pct: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class BackupHardeningReport(BaseModel):
    total_controls: int = 0
    implemented_count: int = 0
    coverage_pct: float = 0.0
    by_control: dict[str, int] = Field(
        default_factory=dict,
    )
    by_status: dict[str, int] = Field(
        default_factory=dict,
    )
    recommendations: list[str] = Field(
        default_factory=list,
    )
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class BackupHardeningEngine:
    """Assess and harden backup controls."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[BackupHardeningRecord] = []
        logger.info(
            "backup_hardening.initialized",
            max_records=max_records,
        )

    def _evict(self) -> None:
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]

    def add_record(
        self,
        **kwargs: Any,
    ) -> BackupHardeningRecord:
        record = BackupHardeningRecord(**kwargs)
        self._records.append(record)
        self._evict()
        logger.info(
            "backup_hardening.record_added",
            record_id=record.id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> BackupHardeningAnalysis:
        matches = [r for r in self._records if r.backup_target == key]
        if not matches:
            return BackupHardeningAnalysis(
                backup_target=key,
            )
        impl = sum(
            1
            for r in matches
            if r.status
            in (
                ImplementationStatus.IMPLEMENTED,
                ImplementationStatus.VERIFIED,
            )
        )
        total = len(matches)
        return BackupHardeningAnalysis(
            backup_target=key,
            controls_implemented=impl,
            controls_total=total,
            coverage_pct=round(
                impl / total * 100,
                2,
            )
            if total
            else 0.0,
        )

    def generate_report(
        self,
    ) -> BackupHardeningReport:
        by_ctrl: dict[str, int] = {}
        by_status: dict[str, int] = {}
        impl = 0
        for r in self._records:
            c = r.control.value
            by_ctrl[c] = by_ctrl.get(c, 0) + 1
            s = r.status.value
            by_status[s] = by_status.get(s, 0) + 1
            if r.status in (
                ImplementationStatus.IMPLEMENTED,
                ImplementationStatus.VERIFIED,
            ):
                impl += 1
        total = len(self._records)
        cov = (
            round(
                impl / total * 100,
                2,
            )
            if total
            else 0.0
        )
        recs: list[str] = []
        if cov < 80:
            recs.append(f"Coverage {cov}% — below 80% target")
        failed = by_status.get("failed", 0)
        if failed > 0:
            recs.append(f"{failed} control(s) failed")
        if not recs:
            recs.append("Backup hardening on track")
        return BackupHardeningReport(
            total_controls=total,
            implemented_count=impl,
            coverage_pct=cov,
            by_control=by_ctrl,
            by_status=by_status,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("backup_hardening.cleared")
        return {"status": "cleared"}

    # -- domain methods --

    def assess_controls(
        self,
        backup_target: str,
    ) -> dict[str, Any]:
        """Assess hardening controls for a target."""
        matches = [r for r in self._records if r.backup_target == backup_target]
        if not matches:
            return {
                "backup_target": backup_target,
                "found": False,
            }
        impl = sum(
            1
            for r in matches
            if r.status
            in (
                ImplementationStatus.IMPLEMENTED,
                ImplementationStatus.VERIFIED,
            )
        )
        return {
            "backup_target": backup_target,
            "found": True,
            "total_controls": len(matches),
            "implemented": impl,
            "coverage_pct": round(
                impl / len(matches) * 100,
                2,
            ),
        }

    def prioritize_hardening(
        self,
    ) -> list[dict[str, Any]]:
        """Prioritize unimplemented controls."""
        unimpl = [
            r
            for r in self._records
            if r.status
            in (
                ImplementationStatus.NOT_STARTED,
                ImplementationStatus.FAILED,
            )
        ]
        priority_order = {
            RiskReduction.CRITICAL: 0,
            RiskReduction.HIGH: 1,
            RiskReduction.MEDIUM: 2,
            RiskReduction.LOW: 3,
            RiskReduction.NONE: 4,
        }
        unimpl.sort(
            key=lambda r: priority_order.get(
                r.risk_reduction,
                4,
            ),
        )
        return [
            {
                "record_id": r.id,
                "control": r.control.value,
                "target": r.backup_target,
                "risk_reduction": (r.risk_reduction.value),
            }
            for r in unimpl
        ]

    def measure_risk_reduction(
        self,
    ) -> dict[str, Any]:
        """Measure overall risk reduction."""
        by_rr: dict[str, int] = {}
        for r in self._records:
            if r.status in (
                ImplementationStatus.IMPLEMENTED,
                ImplementationStatus.VERIFIED,
            ):
                rr = r.risk_reduction.value
                by_rr[rr] = by_rr.get(rr, 0) + 1
        return {
            "implemented_by_reduction": by_rr,
            "total_implemented": sum(by_rr.values()),
        }
