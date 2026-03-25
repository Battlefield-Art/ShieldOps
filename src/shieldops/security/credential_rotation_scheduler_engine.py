"""Credential Rotation Scheduler Engine — schedule and track credential rotation compliance."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RotationPolicy(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ON_COMPROMISE = "on_compromise"
    MANUAL = "manual"


class RotationStatus(StrEnum):
    ON_SCHEDULE = "on_schedule"
    OVERDUE = "overdue"
    FAILED = "failed"
    COMPLETED = "completed"
    SKIPPED = "skipped"


class CredentialRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    COMPLIANT = "compliant"


# --- Models ---


class RotationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    credential_id: str = ""
    rotation_policy: RotationPolicy = RotationPolicy.MONTHLY
    rotation_status: RotationStatus = RotationStatus.ON_SCHEDULE
    credential_risk: CredentialRisk = CredentialRisk.COMPLIANT
    last_rotated: float = Field(default_factory=time.time)
    next_rotation: float = Field(default_factory=time.time)
    days_overdue: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class RotationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    credential_id: str = ""
    rotation_policy: RotationPolicy = RotationPolicy.MONTHLY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RotationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    overdue_count: int = 0
    failed_count: int = 0
    avg_days_overdue: float = 0.0
    by_policy: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_risk: dict[str, int] = Field(default_factory=dict)
    top_overdue: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CredentialRotationSchedulerEngine:
    """Schedule and track credential rotation compliance."""

    def __init__(
        self,
        max_records: int = 200000,
        overdue_threshold: float = 30.0,
    ) -> None:
        self._max_records = max_records
        self._overdue_threshold = overdue_threshold
        self._records: list[RotationRecord] = []
        self._analyses: list[RotationAnalysis] = []
        logger.info(
            "credential_rotation_scheduler_engine.initialized",
            max_records=max_records,
            overdue_threshold=overdue_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        credential_id: str,
        rotation_policy: RotationPolicy = RotationPolicy.MONTHLY,
        rotation_status: RotationStatus = RotationStatus.ON_SCHEDULE,
        credential_risk: CredentialRisk = CredentialRisk.COMPLIANT,
        last_rotated: float = 0.0,
        next_rotation: float = 0.0,
        days_overdue: int = 0,
        service: str = "",
        team: str = "",
    ) -> RotationRecord:
        record = RotationRecord(
            credential_id=credential_id,
            rotation_policy=rotation_policy,
            rotation_status=rotation_status,
            credential_risk=credential_risk,
            last_rotated=last_rotated or time.time(),
            next_rotation=next_rotation or time.time(),
            days_overdue=days_overdue,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "credential_rotation_scheduler_engine.record_added",
            record_id=record.id,
            credential_id=credential_id,
            rotation_status=rotation_status.value,
        )
        return record

    def get_record(self, record_id: str) -> RotationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        rotation_policy: RotationPolicy | None = None,
        rotation_status: RotationStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[RotationRecord]:
        results = list(self._records)
        if rotation_policy is not None:
            results = [r for r in results if r.rotation_policy == rotation_policy]
        if rotation_status is not None:
            results = [r for r in results if r.rotation_status == rotation_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        credential_id: str,
        rotation_policy: RotationPolicy = RotationPolicy.MONTHLY,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> RotationAnalysis:
        analysis = RotationAnalysis(
            credential_id=credential_id,
            rotation_policy=rotation_policy,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "credential_rotation_scheduler_engine.analysis_added",
            credential_id=credential_id,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_rotation_compliance(self) -> dict[str, Any]:
        """Group by rotation_policy; return count and avg days_overdue."""
        policy_data: dict[str, list[int]] = {}
        for r in self._records:
            key = r.rotation_policy.value
            policy_data.setdefault(key, []).append(r.days_overdue)
        result: dict[str, Any] = {}
        for policy, days in policy_data.items():
            result[policy] = {
                "count": len(days),
                "avg_days_overdue": round(sum(days) / len(days), 2),
            }
        return result

    def identify_overdue_credentials(self) -> list[dict[str, Any]]:
        """Return records where days_overdue > overdue_threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.days_overdue > self._overdue_threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "credential_id": r.credential_id,
                        "rotation_policy": r.rotation_policy.value,
                        "days_overdue": r.days_overdue,
                        "credential_risk": r.credential_risk.value,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["days_overdue"], reverse=True)

    def detect_rotation_trends(self) -> dict[str, Any]:
        """Split-half comparison on analysis_score; delta threshold 5.0."""
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [c.analysis_score for c in self._analyses]
        mid = len(vals) // 2
        first_half = vals[:mid]
        second_half = vals[mid:]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        delta = round(avg_second - avg_first, 2)
        if abs(delta) < 5.0:
            trend = "stable"
        elif delta > 0:
            trend = "improving"
        else:
            trend = "degrading"
        return {
            "trend": trend,
            "delta": delta,
            "avg_first_half": round(avg_first, 2),
            "avg_second_half": round(avg_second, 2),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> RotationReport:
        by_policy: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        for r in self._records:
            by_policy[r.rotation_policy.value] = by_policy.get(r.rotation_policy.value, 0) + 1
            by_status[r.rotation_status.value] = by_status.get(r.rotation_status.value, 0) + 1
            by_risk[r.credential_risk.value] = by_risk.get(r.credential_risk.value, 0) + 1
        overdue_count = sum(1 for r in self._records if r.days_overdue > self._overdue_threshold)
        failed_count = sum(1 for r in self._records if r.rotation_status == RotationStatus.FAILED)
        days = [r.days_overdue for r in self._records if r.days_overdue > 0]
        avg_days_overdue = round(sum(days) / len(days), 2) if days else 0.0
        overdue_list = self.identify_overdue_credentials()
        top_overdue = [o["credential_id"] for o in overdue_list[:5]]
        recs: list[str] = []
        if overdue_count > 0:
            recs.append(
                f"{overdue_count} credential(s) overdue for rotation "
                f"(>{self._overdue_threshold} days)"
            )
        if failed_count > 0:
            recs.append(f"{failed_count} rotation(s) failed — investigate and retry")
        if not recs:
            recs.append("All credentials are on schedule for rotation")
        return RotationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            overdue_count=overdue_count,
            failed_count=failed_count,
            avg_days_overdue=avg_days_overdue,
            by_policy=by_policy,
            by_status=by_status,
            by_risk=by_risk,
            top_overdue=top_overdue,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("credential_rotation_scheduler_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        policy_dist: dict[str, int] = {}
        for r in self._records:
            key = r.rotation_policy.value
            policy_dist[key] = policy_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "overdue_threshold": self._overdue_threshold,
            "policy_distribution": policy_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
