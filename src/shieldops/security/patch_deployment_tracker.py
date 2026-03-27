"""Patch Deployment Tracker — track patch rollouts."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DeploymentPhase(StrEnum):
    STAGING = "staging"
    CANARY = "canary"
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"
    COMPLETED = "completed"
    ROLLED_BACK = "rolled_back"


class PatchResult(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    PENDING = "pending"


class RollbackReason(StrEnum):
    HEALTH_CHECK_FAIL = "health_check_fail"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    ERROR_RATE_SPIKE = "error_rate_spike"
    MANUAL_OVERRIDE = "manual_override"
    TIMEOUT = "timeout"


# --- Models ---


class PatchDeploymentRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    patch_id: str = ""
    target_host: str = ""
    phase: DeploymentPhase = DeploymentPhase.STAGING
    result: PatchResult = PatchResult.PENDING
    rollback_reason: str = ""
    duration_sec: float = 0.0
    error_msg: str = ""
    created_at: float = Field(default_factory=time.time)


class PatchDeploymentAnalysis(BaseModel):
    patch_id: str = ""
    total_targets: int = 0
    success_count: int = 0
    failure_count: int = 0
    rollback_count: int = 0
    success_rate_pct: float = 0.0
    avg_duration_sec: float = 0.0
    common_rollback_reason: str = ""
    analyzed_at: float = Field(default_factory=time.time)


class PatchDeploymentReport(BaseModel):
    total_deployments: int = 0
    overall_success_rate_pct: float = 0.0
    rollback_rate_pct: float = 0.0
    by_phase: dict[str, int] = Field(default_factory=dict)
    by_result: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class PatchDeploymentTracker:
    """Track patch deployment lifecycle."""

    def __init__(self, max_records: int = 10000) -> None:
        self._max = max_records
        self._records: list[PatchDeploymentRecord] = []
        logger.info(
            "patch_deployment_tracker.init",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> PatchDeploymentRecord:
        rec = PatchDeploymentRecord(**kwargs)
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "patch_deployment_tracker.recorded",
            record_id=rec.id,
            patch_id=rec.patch_id,
        )
        return rec

    def process(self, patch_id: str) -> PatchDeploymentAnalysis:
        recs = [r for r in self._records if r.patch_id == patch_id]
        if not recs:
            return PatchDeploymentAnalysis(patch_id=patch_id)
        successes = [r for r in recs if r.result == PatchResult.SUCCESS]
        failures = [r for r in recs if r.result == PatchResult.FAILED]
        rollbacks = [r for r in recs if r.phase == DeploymentPhase.ROLLED_BACK]
        durations = [r.duration_sec for r in recs if r.duration_sec > 0]
        avg_dur = round(sum(durations) / len(durations), 2) if durations else 0.0
        reasons: dict[str, int] = {}
        for r in rollbacks:
            if r.rollback_reason:
                reasons[r.rollback_reason] = reasons.get(r.rollback_reason, 0) + 1
        common = max(reasons, key=reasons.get) if reasons else ""
        rate = round(len(successes) / len(recs) * 100, 2)
        return PatchDeploymentAnalysis(
            patch_id=patch_id,
            total_targets=len(recs),
            success_count=len(successes),
            failure_count=len(failures),
            rollback_count=len(rollbacks),
            success_rate_pct=rate,
            avg_duration_sec=avg_dur,
            common_rollback_reason=common,
        )

    def generate_report(self) -> PatchDeploymentReport:
        by_phase: dict[str, int] = {}
        by_result: dict[str, int] = {}
        for r in self._records:
            p = r.phase.value
            by_phase[p] = by_phase.get(p, 0) + 1
            v = r.result.value
            by_result[v] = by_result.get(v, 0) + 1
        total = len(self._records)
        succ = sum(1 for r in self._records if r.result == PatchResult.SUCCESS)
        rb = sum(1 for r in self._records if r.phase == DeploymentPhase.ROLLED_BACK)
        s_rate = round(succ / total * 100, 2) if total else 0.0
        r_rate = round(rb / total * 100, 2) if total else 0.0
        recs: list[str] = []
        if r_rate > 10:
            recs.append("High rollback rate — review canary")
        if s_rate < 90:
            recs.append("Success rate below 90% target")
        if not recs:
            recs.append("Deployments healthy")
        return PatchDeploymentReport(
            total_deployments=total,
            overall_success_rate_pct=s_rate,
            rollback_rate_pct=r_rate,
            by_phase=by_phase,
            by_result=by_result,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max,
            "unique_patches": len({r.patch_id for r in self._records}),
        }

    def clear_data(self) -> None:
        self._records.clear()
        logger.info("patch_deployment_tracker.cleared")

    # -- domain methods --

    def track_deployment(
        self,
        patch_id: str,
        target_host: str,
        phase: DeploymentPhase,
        result: PatchResult,
        duration_sec: float = 0.0,
        rollback_reason: str = "",
    ) -> PatchDeploymentRecord:
        """Record a single deployment event."""
        return self.add_record(
            patch_id=patch_id,
            target_host=target_host,
            phase=phase,
            result=result,
            duration_sec=duration_sec,
            rollback_reason=rollback_reason,
        )

    def measure_success_rate(self, patch_id: str | None = None) -> dict[str, Any]:
        """Measure success rate overall or per patch."""
        recs = self._records
        if patch_id:
            recs = [r for r in recs if r.patch_id == patch_id]
        total = len(recs)
        succ = sum(1 for r in recs if r.result == PatchResult.SUCCESS)
        rate = round(succ / total * 100, 2) if total else 0.0
        return {
            "patch_id": patch_id or "all",
            "total": total,
            "successes": succ,
            "success_rate_pct": rate,
        }

    def detect_rollback_patterns(
        self,
    ) -> list[dict[str, Any]]:
        """Identify recurring rollback causes."""
        reasons: dict[str, list[str]] = {}
        for r in self._records:
            if r.phase == DeploymentPhase.ROLLED_BACK and r.rollback_reason:
                reasons.setdefault(r.rollback_reason, []).append(r.patch_id)
        return [
            {
                "reason": reason,
                "count": len(patches),
                "patches": list(set(patches))[:10],
            }
            for reason, patches in sorted(
                reasons.items(),
                key=lambda x: len(x[1]),
                reverse=True,
            )
        ]
