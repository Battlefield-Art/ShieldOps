"""Cyber Recovery Tracker — track recovery ops and RTO/RPO."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RecoveryPhase(StrEnum):
    DETECTION = "detection"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RESTORATION = "restoration"
    VALIDATION = "validation"


class RecoveryMethod(StrEnum):
    SNAPSHOT_RESTORE = "snapshot_restore"
    CLEAN_ROOM_REBUILD = "clean_room_rebuild"
    BACKUP_RESTORE = "backup_restore"
    FAILOVER = "failover"
    MANUAL_REBUILD = "manual_rebuild"


class RecoveryOutcome(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    IN_PROGRESS = "in_progress"
    ABORTED = "aborted"


# --- Models ---


class CyberRecoveryRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    phase: RecoveryPhase = RecoveryPhase.DETECTION
    method: RecoveryMethod = RecoveryMethod.BACKUP_RESTORE
    outcome: RecoveryOutcome = RecoveryOutcome.IN_PROGRESS
    target_system: str = ""
    rto_target_min: float = 0.0
    rpo_target_min: float = 0.0
    actual_rto_min: float = 0.0
    actual_rpo_min: float = 0.0
    data_loss_gb: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CyberRecoveryAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    phase: RecoveryPhase = RecoveryPhase.DETECTION
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CyberRecoveryReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_rto_min: float = 0.0
    avg_rpo_min: float = 0.0
    rto_breach_count: int = 0
    rpo_breach_count: int = 0
    by_phase: dict[str, int] = Field(default_factory=dict)
    by_method: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class CyberRecoveryTracker:
    """Track recovery operations and RTO/RPO metrics."""

    def __init__(
        self,
        max_records: int = 200000,
        rto_threshold_min: float = 60.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = rto_threshold_min
        self._records: list[CyberRecoveryRecord] = []
        self._analyses: list[CyberRecoveryAnalysis] = []
        logger.info(
            "cyber_recovery_tracker.initialized",
            max_records=max_records,
            rto_threshold_min=rto_threshold_min,
        )

    # -- record / get / list -----------------------------------

    def add_record(
        self,
        incident_id: str,
        phase: RecoveryPhase = RecoveryPhase.DETECTION,
        method: RecoveryMethod = RecoveryMethod.BACKUP_RESTORE,
        outcome: RecoveryOutcome = RecoveryOutcome.IN_PROGRESS,
        target_system: str = "",
        rto_target_min: float = 0.0,
        rpo_target_min: float = 0.0,
        actual_rto_min: float = 0.0,
        actual_rpo_min: float = 0.0,
        data_loss_gb: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> CyberRecoveryRecord:
        record = CyberRecoveryRecord(
            incident_id=incident_id,
            phase=phase,
            method=method,
            outcome=outcome,
            target_system=target_system,
            rto_target_min=rto_target_min,
            rpo_target_min=rpo_target_min,
            actual_rto_min=actual_rto_min,
            actual_rpo_min=actual_rpo_min,
            data_loss_gb=data_loss_gb,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "cyber_recovery_tracker.record_added",
            record_id=record.id,
            incident_id=incident_id,
            phase=phase.value,
            outcome=outcome.value,
        )
        return record

    def get_record(self, record_id: str) -> CyberRecoveryRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        phase: RecoveryPhase | None = None,
        outcome: RecoveryOutcome | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CyberRecoveryRecord]:
        results = list(self._records)
        if phase is not None:
            results = [r for r in results if r.phase == phase]
        if outcome is not None:
            results = [r for r in results if r.outcome == outcome]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def process(self, incident_id: str) -> CyberRecoveryAnalysis:
        matched = [r for r in self._records if r.incident_id == incident_id]
        rto_vals = [r.actual_rto_min for r in matched]
        avg_rto = round(sum(rto_vals) / len(rto_vals), 2) if rto_vals else 0.0
        breached = avg_rto > self._threshold
        analysis = CyberRecoveryAnalysis(
            incident_id=incident_id,
            phase=(matched[-1].phase if matched else RecoveryPhase.DETECTION),
            analysis_score=avg_rto,
            threshold=self._threshold,
            breached=breached,
            description=(f"Avg RTO {avg_rto}min for {incident_id}"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "cyber_recovery_tracker.processed",
            incident_id=incident_id,
            avg_rto=avg_rto,
            breached=breached,
        )
        return analysis

    # -- domain operations ------------------------------------

    def track_recovery(
        self,
        incident_id: str,
        phase: RecoveryPhase,
        method: RecoveryMethod,
        target_system: str = "",
        rto_target_min: float = 60.0,
        rpo_target_min: float = 15.0,
    ) -> dict[str, Any]:
        """Track a recovery operation for an incident."""
        record = self.add_record(
            incident_id=incident_id,
            phase=phase,
            method=method,
            target_system=target_system,
            rto_target_min=rto_target_min,
            rpo_target_min=rpo_target_min,
        )
        return {
            "record_id": record.id,
            "incident_id": incident_id,
            "phase": phase.value,
            "method": method.value,
            "target_system": target_system,
            "rto_target_min": rto_target_min,
            "rpo_target_min": rpo_target_min,
        }

    def calculate_rto_rpo(self, incident_id: str) -> dict[str, Any]:
        """Calculate RTO/RPO metrics for an incident."""
        matched = [r for r in self._records if r.incident_id == incident_id]
        if not matched:
            return {
                "incident_id": incident_id,
                "found": False,
            }
        rto_vals = [r.actual_rto_min for r in matched]
        rpo_vals = [r.actual_rpo_min for r in matched]
        avg_rto = round(sum(rto_vals) / len(rto_vals), 2)
        avg_rpo = round(sum(rpo_vals) / len(rpo_vals), 2)
        rto_breaches = sum(1 for r in matched if r.actual_rto_min > r.rto_target_min > 0)
        rpo_breaches = sum(1 for r in matched if r.actual_rpo_min > r.rpo_target_min > 0)
        total_loss = round(sum(r.data_loss_gb for r in matched), 2)
        return {
            "incident_id": incident_id,
            "found": True,
            "record_count": len(matched),
            "avg_rto_min": avg_rto,
            "avg_rpo_min": avg_rpo,
            "rto_breaches": rto_breaches,
            "rpo_breaches": rpo_breaches,
            "total_data_loss_gb": total_loss,
        }

    def assess_readiness(self) -> dict[str, Any]:
        """Assess overall recovery readiness."""
        if not self._records:
            return {
                "readiness_score": 0.0,
                "total_recoveries": 0,
            }
        success_ct = sum(1 for r in self._records if r.outcome == RecoveryOutcome.SUCCESS)
        total = len(self._records)
        success_rate = round(success_ct / total * 100, 2)
        rto_breaches = sum(1 for r in self._records if r.actual_rto_min > r.rto_target_min > 0)
        breach_rate = round(rto_breaches / total * 100, 2)
        readiness = round(success_rate * (1 - breach_rate / 100), 2)
        by_method: dict[str, int] = {}
        for r in self._records:
            key = r.method.value
            by_method[key] = by_method.get(key, 0) + 1
        return {
            "readiness_score": readiness,
            "total_recoveries": total,
            "success_rate_pct": success_rate,
            "rto_breach_rate_pct": breach_rate,
            "by_method": by_method,
        }

    # -- report / stats ----------------------------------------

    def generate_report(self) -> CyberRecoveryReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.phase.value] = by_e1.get(r.phase.value, 0) + 1
            by_e2[r.method.value] = by_e2.get(r.method.value, 0) + 1
            by_e3[r.outcome.value] = by_e3.get(r.outcome.value, 0) + 1
        rto_vals = [r.actual_rto_min for r in self._records]
        rpo_vals = [r.actual_rpo_min for r in self._records]
        avg_rto = round(sum(rto_vals) / len(rto_vals), 2) if rto_vals else 0.0
        avg_rpo = round(sum(rpo_vals) / len(rpo_vals), 2) if rpo_vals else 0.0
        rto_breaches = sum(1 for r in self._records if r.actual_rto_min > r.rto_target_min > 0)
        rpo_breaches = sum(1 for r in self._records if r.actual_rpo_min > r.rpo_target_min > 0)
        gap_count = rto_breaches + rpo_breaches
        top_gaps = [
            r.incident_id for r in self._records if r.actual_rto_min > r.rto_target_min > 0
        ][:5]
        recs: list[str] = []
        if rto_breaches > 0:
            recs.append(f"{rto_breaches} RTO breach(es) detected")
        if rpo_breaches > 0:
            recs.append(f"{rpo_breaches} RPO breach(es) detected")
        if not recs:
            recs.append("Cyber Recovery Tracker is healthy")
        return CyberRecoveryReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_rto_min=avg_rto,
            avg_rpo_min=avg_rpo,
            rto_breach_count=rto_breaches,
            rpo_breach_count=rpo_breaches,
            by_phase=by_e1,
            by_method=by_e2,
            by_outcome=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("cyber_recovery_tracker.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.phase.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "phase_distribution": e1_dist,
            "unique_incidents": len({r.incident_id for r in self._records}),
            "unique_teams": len({r.team for r in self._records}),
        }
