"""Cloud Remediation Tracker — remediation and MTTR."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RemediationType(StrEnum):
    PATCH = "patch"
    CONFIG_FIX = "config_fix"
    ACCESS_REVOKE = "access_revoke"
    RESOURCE_DELETE = "resource_delete"
    POLICY_UPDATE = "policy_update"


class AutomationLevel(StrEnum):
    MANUAL = "manual"
    SEMI_AUTOMATED = "semi_automated"
    FULLY_AUTOMATED = "fully_automated"
    AI_DRIVEN = "ai_driven"
    UNKNOWN = "unknown"


class RemediationOutcome(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    ROLLBACK = "rollback"
    PENDING = "pending"


# --- Models ---


class CloudRemediationRecord(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    finding_id: str = ""
    remediation_type: RemediationType = RemediationType.PATCH
    automation: AutomationLevel = AutomationLevel.MANUAL
    outcome: RemediationOutcome = RemediationOutcome.PENDING
    cloud_provider: str = ""
    account_id: str = ""
    duration_seconds: float = 0.0
    created_at: float = Field(default_factory=time.time)


class CloudRemediationAnalysis(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    account_id: str = ""
    total_remediations: int = 0
    success_rate_pct: float = 0.0
    avg_duration_seconds: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class CloudRemediationReport(BaseModel):
    total_remediations: int = 0
    success_count: int = 0
    failed_count: int = 0
    auto_rate_pct: float = 0.0
    avg_mttr_seconds: float = 0.0
    by_type: dict[str, int] = Field(
        default_factory=dict,
    )
    by_outcome: dict[str, int] = Field(
        default_factory=dict,
    )
    recommendations: list[str] = Field(
        default_factory=list,
    )
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class CloudRemediationTracker:
    """Track cloud remediation and MTTR."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[CloudRemediationRecord] = []
        logger.info(
            "cloud_remediation.initialized",
            max_records=max_records,
        )

    def _evict(self) -> None:
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]

    def record_item(
        self,
        **kwargs: Any,
    ) -> CloudRemediationRecord:
        record = CloudRemediationRecord(**kwargs)
        self._records.append(record)
        self._evict()
        logger.info(
            "cloud_remediation.item_recorded",
            record_id=record.id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> CloudRemediationAnalysis:
        matches = [r for r in self._records if r.account_id == key]
        if not matches:
            return CloudRemediationAnalysis(
                account_id=key,
            )
        successes = sum(1 for r in matches if r.outcome == RemediationOutcome.SUCCESS)
        durations = [r.duration_seconds for r in matches if r.duration_seconds > 0]
        avg_dur = (
            round(
                sum(durations) / len(durations),
                2,
            )
            if durations
            else 0.0
        )
        return CloudRemediationAnalysis(
            account_id=key,
            total_remediations=len(matches),
            success_rate_pct=round(
                successes / len(matches) * 100,
                2,
            ),
            avg_duration_seconds=avg_dur,
        )

    def generate_report(
        self,
    ) -> CloudRemediationReport:
        by_type: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        successes = 0
        failures = 0
        auto_count = 0
        durations: list[float] = []
        for r in self._records:
            t = r.remediation_type.value
            by_type[t] = by_type.get(t, 0) + 1
            o = r.outcome.value
            by_outcome[o] = by_outcome.get(o, 0) + 1
            if r.outcome == RemediationOutcome.SUCCESS:
                successes += 1
            if r.outcome == RemediationOutcome.FAILED:
                failures += 1
            if r.automation in (
                AutomationLevel.FULLY_AUTOMATED,
                AutomationLevel.AI_DRIVEN,
            ):
                auto_count += 1
            if r.duration_seconds > 0:
                durations.append(r.duration_seconds)
        total = len(self._records)
        auto_rate = (
            round(
                auto_count / total * 100,
                2,
            )
            if total
            else 0.0
        )
        avg_mttr = (
            round(
                sum(durations) / len(durations),
                2,
            )
            if durations
            else 0.0
        )
        recs: list[str] = []
        if failures > 0:
            recs.append(f"{failures} failed remediation(s)")
        if auto_rate < 50 and total > 0:
            recs.append("Automation rate below 50%")
        if not recs:
            recs.append("Remediation on track")
        return CloudRemediationReport(
            total_remediations=total,
            success_count=successes,
            failed_count=failures,
            auto_rate_pct=auto_rate,
            avg_mttr_seconds=avg_mttr,
            by_type=by_type,
            by_outcome=by_outcome,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("cloud_remediation.cleared")
        return {"status": "cleared"}

    # -- domain methods --

    def track_remediation(
        self,
        finding_id: str,
        remediation_type: RemediationType,
        account_id: str = "",
    ) -> dict[str, Any]:
        """Track a remediation action."""
        record = self.record_item(
            finding_id=finding_id,
            remediation_type=remediation_type,
            account_id=account_id,
        )
        return {
            "record_id": record.id,
            "finding_id": finding_id,
            "type": remediation_type.value,
        }

    def measure_auto_rate(
        self,
    ) -> dict[str, Any]:
        """Measure automation rate."""
        total = len(self._records)
        if total == 0:
            return {"total": 0, "auto_pct": 0.0}
        auto = sum(
            1
            for r in self._records
            if r.automation
            in (
                AutomationLevel.FULLY_AUTOMATED,
                AutomationLevel.AI_DRIVEN,
            )
        )
        return {
            "total": total,
            "automated": auto,
            "auto_pct": round(
                auto / total * 100,
                2,
            ),
        }

    def calculate_mttr(
        self,
    ) -> dict[str, Any]:
        """Calculate mean time to remediation."""
        durations = [
            r.duration_seconds
            for r in self._records
            if r.duration_seconds > 0 and r.outcome == RemediationOutcome.SUCCESS
        ]
        if not durations:
            return {"mttr_seconds": 0.0, "count": 0}
        return {
            "mttr_seconds": round(
                sum(durations) / len(durations),
                2,
            ),
            "count": len(durations),
        }
