"""Backup Recovery Tester — test and track recovery."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TestType(StrEnum):
    FULL_RESTORE = "full_restore"
    PARTIAL_RESTORE = "partial_restore"
    FILE_LEVEL = "file_level"
    DATABASE = "database"
    DISASTER_RECOVERY = "disaster_recovery"


class TestResult(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


class RecoveryCoverage(StrEnum):
    FULL = "full"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    NONE = "none"


# --- Models ---


class BackupTestRecord(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    backup_id: str = ""
    test_type: TestType = TestType.FULL_RESTORE
    result: TestResult = TestResult.PASSED
    coverage: RecoveryCoverage = RecoveryCoverage.FULL
    duration_seconds: float = 0.0
    data_size_gb: float = 0.0
    environment: str = ""
    created_at: float = Field(default_factory=time.time)


class BackupTestAnalysis(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    backup_id: str = ""
    tests_run: int = 0
    pass_rate_pct: float = 0.0
    avg_duration: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class BackupTestReport(BaseModel):
    total_tests: int = 0
    passed_count: int = 0
    failed_count: int = 0
    pass_rate_pct: float = 0.0
    avg_duration_seconds: float = 0.0
    by_type: dict[str, int] = Field(
        default_factory=dict,
    )
    by_result: dict[str, int] = Field(
        default_factory=dict,
    )
    recommendations: list[str] = Field(
        default_factory=list,
    )
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class BackupRecoveryTester:
    """Schedule and track backup recovery tests."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[BackupTestRecord] = []
        logger.info(
            "backup_recovery_tester.initialized",
            max_records=max_records,
        )

    def _evict(self) -> None:
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]

    def record_item(
        self,
        **kwargs: Any,
    ) -> BackupTestRecord:
        record = BackupTestRecord(**kwargs)
        self._records.append(record)
        self._evict()
        logger.info(
            "backup_test.item_recorded",
            record_id=record.id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> BackupTestAnalysis:
        matches = [r for r in self._records if r.backup_id == key]
        if not matches:
            return BackupTestAnalysis(backup_id=key)
        passed = sum(1 for r in matches if r.result == TestResult.PASSED)
        durations = [r.duration_seconds for r in matches if r.duration_seconds > 0]
        avg = (
            round(
                sum(durations) / len(durations),
                2,
            )
            if durations
            else 0.0
        )
        return BackupTestAnalysis(
            backup_id=key,
            tests_run=len(matches),
            pass_rate_pct=round(
                passed / len(matches) * 100,
                2,
            ),
            avg_duration=avg,
        )

    def generate_report(self) -> BackupTestReport:
        by_type: dict[str, int] = {}
        by_result: dict[str, int] = {}
        passed = 0
        failed = 0
        durations: list[float] = []
        for r in self._records:
            t = r.test_type.value
            by_type[t] = by_type.get(t, 0) + 1
            rv = r.result.value
            by_result[rv] = by_result.get(rv, 0) + 1
            if r.result == TestResult.PASSED:
                passed += 1
            if r.result == TestResult.FAILED:
                failed += 1
            if r.duration_seconds > 0:
                durations.append(r.duration_seconds)
        total = len(self._records)
        rate = (
            round(
                passed / total * 100,
                2,
            )
            if total
            else 0.0
        )
        avg_dur = (
            round(
                sum(durations) / len(durations),
                2,
            )
            if durations
            else 0.0
        )
        recs: list[str] = []
        if failed > 0:
            recs.append(f"{failed} test(s) failed")
        if rate < 90 and total > 0:
            recs.append("Pass rate below 90%")
        if not recs:
            recs.append("Backup recovery healthy")
        return BackupTestReport(
            total_tests=total,
            passed_count=passed,
            failed_count=failed,
            pass_rate_pct=rate,
            avg_duration_seconds=avg_dur,
            by_type=by_type,
            by_result=by_result,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("backup_recovery_tester.cleared")
        return {"status": "cleared"}

    # -- domain methods --

    def schedule_test(
        self,
        backup_id: str,
        test_type: TestType,
    ) -> dict[str, Any]:
        """Schedule a recovery test."""
        record = self.record_item(
            backup_id=backup_id,
            test_type=test_type,
            result=TestResult.SKIPPED,
        )
        return {
            "record_id": record.id,
            "backup_id": backup_id,
            "test_type": test_type.value,
            "scheduled": True,
        }

    def execute_recovery_test(
        self,
        backup_id: str,
        test_type: TestType = TestType.FULL_RESTORE,
    ) -> dict[str, Any]:
        """Execute a recovery test (simulated)."""
        record = self.record_item(
            backup_id=backup_id,
            test_type=test_type,
            result=TestResult.PASSED,
            duration_seconds=120.0,
        )
        return {
            "record_id": record.id,
            "backup_id": backup_id,
            "result": "passed",
            "duration_seconds": 120.0,
        }

    def track_coverage(
        self,
    ) -> dict[str, Any]:
        """Track recovery test coverage."""
        backups = {r.backup_id for r in self._records}
        tested = {r.backup_id for r in self._records if r.result != TestResult.SKIPPED}
        return {
            "total_backups": len(backups),
            "tested": len(tested),
            "coverage_pct": round(
                len(tested) / len(backups) * 100,
                2,
            )
            if backups
            else 0.0,
        }
