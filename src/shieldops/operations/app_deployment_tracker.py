"""App Deployment Tracker — track deployments, health, and rollbacks."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DeployStage(StrEnum):
    BUILDING = "building"
    TESTING = "testing"
    STAGING = "staging"
    CANARY = "canary"
    PRODUCTION = "production"


class DeployOutcome(StrEnum):
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    IN_PROGRESS = "in_progress"


class RollbackReason(StrEnum):
    ERROR_RATE_SPIKE = "error_rate_spike"
    LATENCY_REGRESSION = "latency_regression"
    HEALTH_CHECK_FAIL = "health_check_fail"
    MANUAL_DECISION = "manual_decision"
    SLO_BREACH = "slo_breach"


# --- Models ---


class DeploymentRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    app_name: str = ""
    version: str = ""
    stage: DeployStage = DeployStage.BUILDING
    outcome: DeployOutcome = DeployOutcome.IN_PROGRESS
    rollback_reason: RollbackReason | None = None
    duration_seconds: float = 0.0
    health_score: float = 1.0
    deployer: str = ""
    created_at: float = Field(default_factory=time.time)


class DeploymentAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    deployment_id: str = ""
    risk_score: float = 0.0
    checks_passed: int = 0
    checks_total: int = 0
    analyzed_at: float = Field(default_factory=time.time)


class DeploymentReport(BaseModel):
    total_deployments: int = 0
    success_count: int = 0
    rollback_count: int = 0
    avg_duration_seconds: float = 0.0
    by_stage: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    by_rollback_reason: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AppDeploymentTracker:
    """Track application deployments, health, and rollbacks."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[DeploymentRecord] = []
        logger.info(
            "app_deployment_tracker.initialized",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> DeploymentRecord:
        record = DeploymentRecord(**kwargs)
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "app_deployment_tracker.record_added",
            record_id=record.id,
            app_name=record.app_name,
        )
        return record

    def process(self, key: str) -> dict[str, Any]:
        matches = [r for r in self._records if r.id == key]
        if not matches:
            return {"found": False, "key": key}
        rec = matches[0]
        return {
            "found": True,
            "id": rec.id,
            "app_name": rec.app_name,
            "outcome": rec.outcome.value,
        }

    # -- domain methods --

    def track_deployment(
        self,
        app_name: str,
        version: str,
        stage: DeployStage = DeployStage.PRODUCTION,
        outcome: DeployOutcome = DeployOutcome.SUCCESS,
        duration_seconds: float = 0.0,
        deployer: str = "",
    ) -> DeploymentRecord:
        """Track a deployment event."""
        record = self.add_record(
            app_name=app_name,
            version=version,
            stage=stage,
            outcome=outcome,
            duration_seconds=duration_seconds,
            deployer=deployer,
        )
        logger.info(
            "app_deployment_tracker.deployment_tracked",
            app_name=app_name,
            version=version,
            outcome=outcome.value,
        )
        return record

    def validate_health(self, deployment_id: str) -> dict[str, Any]:
        """Validate health of a deployment."""
        record = None
        for r in self._records:
            if r.id == deployment_id:
                record = r
                break
        if record is None:
            return {"found": False, "deployment_id": deployment_id}
        healthy = record.health_score >= 0.8
        return {
            "found": True,
            "deployment_id": deployment_id,
            "app_name": record.app_name,
            "health_score": record.health_score,
            "healthy": healthy,
            "stage": record.stage.value,
        }

    def trigger_rollback(
        self,
        deployment_id: str,
        reason: RollbackReason = RollbackReason.MANUAL_DECISION,
    ) -> dict[str, Any]:
        """Trigger rollback for a deployment."""
        record = None
        for r in self._records:
            if r.id == deployment_id:
                record = r
                break
        if record is None:
            return {"found": False, "deployment_id": deployment_id}
        previous_outcome = record.outcome.value
        record.outcome = DeployOutcome.ROLLED_BACK
        record.rollback_reason = reason
        logger.info(
            "app_deployment_tracker.rollback_triggered",
            deployment_id=deployment_id,
            reason=reason.value,
        )
        return {
            "found": True,
            "deployment_id": deployment_id,
            "app_name": record.app_name,
            "previous_outcome": previous_outcome,
            "new_outcome": "rolled_back",
            "reason": reason.value,
        }

    # -- report / stats --

    def generate_report(self) -> DeploymentReport:
        by_stage: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        by_rollback: dict[str, int] = {}
        total_dur = 0.0
        for r in self._records:
            by_stage[r.stage.value] = by_stage.get(r.stage.value, 0) + 1
            by_outcome[r.outcome.value] = by_outcome.get(r.outcome.value, 0) + 1
            if r.rollback_reason is not None:
                rr = r.rollback_reason.value
                by_rollback[rr] = by_rollback.get(rr, 0) + 1
            total_dur += r.duration_seconds
        success = by_outcome.get("success", 0)
        rollbacks = by_outcome.get("rolled_back", 0)
        avg_dur = round(total_dur / len(self._records), 2) if self._records else 0.0
        recs: list[str] = []
        if rollbacks > 0:
            recs.append(f"{rollbacks} rollback(s) occurred")
        failed = by_outcome.get("failed", 0)
        if failed > 0:
            recs.append(f"{failed} deployment(s) failed")
        if not recs:
            recs.append("Deployments operating normally")
        return DeploymentReport(
            total_deployments=len(self._records),
            success_count=success,
            rollback_count=rollbacks,
            avg_duration_seconds=avg_dur,
            by_stage=by_stage,
            by_outcome=by_outcome,
            by_rollback_reason=by_rollback,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "success_rate": (
                round(
                    sum(1 for r in self._records if r.outcome == DeployOutcome.SUCCESS)
                    / len(self._records)
                    * 100,
                    2,
                )
                if self._records
                else 0.0
            ),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("app_deployment_tracker.cleared")
        return {"status": "cleared"}
