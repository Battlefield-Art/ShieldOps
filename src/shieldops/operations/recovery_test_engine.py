"""Recovery Test Engine —
track disaster recovery test results,
validate RPO/RTO compliance, manage test cadence."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RecoveryType(StrEnum):
    FULL_RESTORE = "full_restore"
    POINT_IN_TIME = "point_in_time"
    PARTIAL = "partial"
    TABLE_LEVEL = "table_level"
    FILE_LEVEL = "file_level"


class TestOutcome(StrEnum):
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    DATA_LOSS = "data_loss"


class RPOCompliance(StrEnum):
    WITHIN_TARGET = "within_target"
    EXCEEDED = "exceeded"
    FAR_EXCEEDED = "far_exceeded"
    NOT_MEASURED = "not_measured"
    NA = "na"


# --- Models ---


class RecoveryTestRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    test_name: str = ""
    service_name: str = ""
    recovery_type: RecoveryType = RecoveryType.FULL_RESTORE
    test_outcome: TestOutcome = TestOutcome.SUCCESS
    rpo_compliance: RPOCompliance = RPOCompliance.WITHIN_TARGET
    recovery_time_minutes: float = 0.0
    data_loss_minutes: float = 0.0
    data_recovered_pct: float = 100.0
    target_rpo_minutes: float = 15.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RecoveryTestAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_name: str = ""
    recovery_type: RecoveryType = RecoveryType.FULL_RESTORE
    avg_recovery_time: float = 0.0
    success_rate: float = 0.0
    rpo_compliance_rate: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RecoveryTestReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_recovery_time: float = 0.0
    by_recovery_type: dict[str, int] = Field(default_factory=dict)
    by_test_outcome: dict[str, int] = Field(default_factory=dict)
    by_rpo_compliance: dict[str, int] = Field(default_factory=dict)
    failing_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class RecoveryTestEngine:
    """Track disaster recovery test results,
    validate RPO/RTO compliance, manage test cadence."""

    def __init__(self, max_records: int = 200000, rpo_threshold: float = 15.0) -> None:
        self._max_records = max_records
        self._rpo_threshold = rpo_threshold
        self._records: list[RecoveryTestRecord] = []
        self._analyses: dict[str, RecoveryTestAnalysis] = {}
        logger.info(
            "recovery_test_engine.init",
            max_records=max_records,
            rpo_threshold=rpo_threshold,
        )

    def add_record(
        self,
        test_name: str = "",
        service_name: str = "",
        recovery_type: RecoveryType = RecoveryType.FULL_RESTORE,
        test_outcome: TestOutcome = TestOutcome.SUCCESS,
        rpo_compliance: RPOCompliance = RPOCompliance.WITHIN_TARGET,
        recovery_time_minutes: float = 0.0,
        data_loss_minutes: float = 0.0,
        data_recovered_pct: float = 100.0,
        target_rpo_minutes: float = 15.0,
        description: str = "",
    ) -> RecoveryTestRecord:
        record = RecoveryTestRecord(
            test_name=test_name,
            service_name=service_name,
            recovery_type=recovery_type,
            test_outcome=test_outcome,
            rpo_compliance=rpo_compliance,
            recovery_time_minutes=recovery_time_minutes,
            data_loss_minutes=data_loss_minutes,
            data_recovered_pct=data_recovered_pct,
            target_rpo_minutes=target_rpo_minutes,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "recovery_test.record_added",
            record_id=record.id,
            test_name=test_name,
        )
        return record

    def process(self, key: str) -> RecoveryTestAnalysis | dict[str, Any]:
        recs = [r for r in self._records if r.service_name == key or r.id == key]
        if not recs:
            return {"status": "not_found", "key": key}
        avg_rt = round(sum(r.recovery_time_minutes for r in recs) / len(recs), 2)
        successes = sum(1 for r in recs if r.test_outcome == TestOutcome.SUCCESS)
        success_rate = round(successes / len(recs) * 100, 2)
        rpo_ok = sum(1 for r in recs if r.rpo_compliance == RPOCompliance.WITHIN_TARGET)
        rpo_rate = round(rpo_ok / len(recs) * 100, 2)
        analysis = RecoveryTestAnalysis(
            service_name=recs[0].service_name,
            recovery_type=recs[0].recovery_type,
            avg_recovery_time=avg_rt,
            success_rate=success_rate,
            rpo_compliance_rate=rpo_rate,
            description=(
                f"{recs[0].service_name} avg_recovery={avg_rt}min "
                f"success={success_rate}% rpo_compliance={rpo_rate}%"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> RecoveryTestReport:
        by_type: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        by_rpo: dict[str, int] = {}
        rts: list[float] = []
        for r in self._records:
            rt = r.recovery_type.value
            by_type[rt] = by_type.get(rt, 0) + 1
            to = r.test_outcome.value
            by_outcome[to] = by_outcome.get(to, 0) + 1
            rp = r.rpo_compliance.value
            by_rpo[rp] = by_rpo.get(rp, 0) + 1
            rts.append(r.recovery_time_minutes)
        avg_rt = round(sum(rts) / len(rts), 2) if rts else 0.0
        failing = list(
            {
                r.service_name
                for r in self._records
                if r.test_outcome in (TestOutcome.FAILED, TestOutcome.DATA_LOSS)
            }
        )[:10]
        recs: list[str] = []
        if failing:
            recs.append(f"{len(failing)} services with failing recovery tests")
        exceeded = by_rpo.get("exceeded", 0) + by_rpo.get("far_exceeded", 0)
        if exceeded:
            recs.append(f"{exceeded} tests exceeded RPO target — review backup frequency")
        if not recs:
            recs.append("All recovery tests within acceptable parameters")
        return RecoveryTestReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_recovery_time=avg_rt,
            by_recovery_type=by_type,
            by_test_outcome=by_outcome,
            by_rpo_compliance=by_rpo,
            failing_services=failing,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        outcome_dist: dict[str, int] = {}
        for r in self._records:
            k = r.test_outcome.value
            outcome_dist[k] = outcome_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "outcome_distribution": outcome_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("recovery_test_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def find_rpo_violations(self) -> list[dict[str, Any]]:
        """Find recovery tests that violated RPO targets."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.data_loss_minutes > self._rpo_threshold:
                results.append(
                    {
                        "test_name": r.test_name,
                        "service_name": r.service_name,
                        "recovery_type": r.recovery_type.value,
                        "data_loss_minutes": r.data_loss_minutes,
                        "target_rpo_minutes": r.target_rpo_minutes,
                        "rpo_compliance": r.rpo_compliance.value,
                        "excess_minutes": round(r.data_loss_minutes - r.target_rpo_minutes, 2),
                    }
                )
        results.sort(key=lambda x: x["data_loss_minutes"], reverse=True)
        return results

    def analyze_recovery_time_trends(self) -> list[dict[str, Any]]:
        """Analyze recovery time trends per service."""
        svc_data: dict[str, list[float]] = {}
        for r in self._records:
            svc_data.setdefault(r.service_name, []).append(r.recovery_time_minutes)
        results: list[dict[str, Any]] = []
        for svc, times in svc_data.items():
            avg_rt = round(sum(times) / len(times), 2)
            min_rt = round(min(times), 2)
            max_rt = round(max(times), 2)
            results.append(
                {
                    "service_name": svc,
                    "test_count": len(times),
                    "avg_recovery_time_min": avg_rt,
                    "min_recovery_time_min": min_rt,
                    "max_recovery_time_min": max_rt,
                }
            )
        results.sort(key=lambda x: x["avg_recovery_time_min"], reverse=True)
        return results

    def rank_services_by_resilience(self) -> list[dict[str, Any]]:
        """Rank services by recovery test resilience score."""
        svc_data: dict[str, list[RecoveryTestRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service_name, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, recs in svc_data.items():
            successes = sum(1 for r in recs if r.test_outcome == TestOutcome.SUCCESS)
            rpo_ok = sum(1 for r in recs if r.rpo_compliance == RPOCompliance.WITHIN_TARGET)
            success_rate = successes / len(recs) * 100 if recs else 0.0
            rpo_rate = rpo_ok / len(recs) * 100 if recs else 0.0
            score = round((success_rate + rpo_rate) / 2, 2)
            results.append(
                {
                    "service_name": svc,
                    "test_count": len(recs),
                    "success_rate": round(success_rate, 2),
                    "rpo_compliance_rate": round(rpo_rate, 2),
                    "resilience_score": score,
                    "rank": 0,
                }
            )
        results.sort(key=lambda x: x["resilience_score"])
        for idx, entry in enumerate(results, 1):
            entry["rank"] = idx
        return results
