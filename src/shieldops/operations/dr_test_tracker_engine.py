"""DR Test Tracker Engine — track disaster recovery test outcomes."""

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
    FAILOVER = "failover"
    BACKUP_RESTORE = "backup_restore"
    REGION_SWITCH = "region_switch"
    DATA_RECOVERY = "data_recovery"
    FULL_DR = "full_dr"


class TestOutcome(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    ABORTED = "aborted"
    SKIPPED = "skipped"


class RTOCompliance(StrEnum):
    WITHIN_TARGET = "within_target"
    EXCEEDED = "exceeded"
    FAR_EXCEEDED = "far_exceeded"
    NOT_MEASURED = "not_measured"
    NA = "na"


# --- Models ---


class DRTestTrackerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str = ""
    test_type: TestType = TestType.FAILOVER
    test_outcome: TestOutcome = TestOutcome.SUCCESS
    rto_compliance: RTOCompliance = RTOCompliance.WITHIN_TARGET
    rto_target_seconds: float = 0.0
    rto_actual_seconds: float = 0.0
    rpo_target_seconds: float = 0.0
    rpo_actual_seconds: float = 0.0
    data_loss_bytes: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DRTestTrackerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str = ""
    analysis_score: float = 0.0
    test_type: TestType = TestType.FAILOVER
    compliant: bool = True
    data_points: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DRTestTrackerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    compliance_rate: float = 0.0
    by_test_type: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    by_rto_compliance: dict[str, int] = Field(default_factory=dict)
    non_compliant_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class DRTestTrackerEngine:
    """Track disaster recovery test outcomes and RTO/RPO compliance."""

    def __init__(
        self,
        max_records: int = 200000,
        compliance_threshold: float = 90.0,
    ) -> None:
        self._max_records = max_records
        self._compliance_threshold = compliance_threshold
        self._records: list[DRTestTrackerRecord] = []
        self._analyses: dict[str, DRTestTrackerAnalysis] = {}
        logger.info(
            "dr_test_tracker_engine.init",
            max_records=max_records,
            compliance_threshold=compliance_threshold,
        )

    def add_record(
        self,
        service_id: str = "",
        test_type: TestType = TestType.FAILOVER,
        test_outcome: TestOutcome = TestOutcome.SUCCESS,
        rto_compliance: RTOCompliance = RTOCompliance.WITHIN_TARGET,
        rto_target_seconds: float = 0.0,
        rto_actual_seconds: float = 0.0,
        rpo_target_seconds: float = 0.0,
        rpo_actual_seconds: float = 0.0,
        data_loss_bytes: int = 0,
        description: str = "",
    ) -> DRTestTrackerRecord:
        record = DRTestTrackerRecord(
            service_id=service_id,
            test_type=test_type,
            test_outcome=test_outcome,
            rto_compliance=rto_compliance,
            rto_target_seconds=rto_target_seconds,
            rto_actual_seconds=rto_actual_seconds,
            rpo_target_seconds=rpo_target_seconds,
            rpo_actual_seconds=rpo_actual_seconds,
            data_loss_bytes=data_loss_bytes,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "dr_test_tracker_engine.record_added",
            record_id=record.id,
            service_id=service_id,
        )
        return record

    def process(self, key: str) -> DRTestTrackerAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        points = sum(1 for r in self._records if r.service_id == rec.service_id)
        compliant = rec.rto_compliance == RTOCompliance.WITHIN_TARGET
        score = 100.0 if compliant else 0.0
        if rec.rto_target_seconds > 0 and rec.rto_actual_seconds > 0:
            ratio = rec.rto_actual_seconds / rec.rto_target_seconds
            score = round(max(0.0, 100.0 - (ratio - 1.0) * 100.0), 2)
        analysis = DRTestTrackerAnalysis(
            service_id=rec.service_id,
            analysis_score=score,
            test_type=rec.test_type,
            compliant=compliant,
            data_points=points,
            description=(
                f"DR test {rec.test_type.value} for {rec.service_id}"
                f" — outcome {rec.test_outcome.value}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> DRTestTrackerReport:
        by_tt: dict[str, int] = {}
        by_o: dict[str, int] = {}
        by_rto: dict[str, int] = {}
        compliant_count = 0
        for r in self._records:
            by_tt[r.test_type.value] = by_tt.get(r.test_type.value, 0) + 1
            by_o[r.test_outcome.value] = by_o.get(r.test_outcome.value, 0) + 1
            by_rto[r.rto_compliance.value] = by_rto.get(r.rto_compliance.value, 0) + 1
            if r.rto_compliance == RTOCompliance.WITHIN_TARGET:
                compliant_count += 1
        total = len(self._records)
        rate = round(compliant_count / total * 100, 2) if total else 0.0
        non_compliant = list(
            {r.service_id for r in self._records if r.rto_compliance != RTOCompliance.WITHIN_TARGET}
        )[:10]
        recs: list[str] = []
        if rate < self._compliance_threshold:
            recs.append(f"RTO compliance {rate}% below threshold {self._compliance_threshold}%")
        failed = sum(
            1 for r in self._records if r.test_outcome in (TestOutcome.FAILED, TestOutcome.ABORTED)
        )
        if failed:
            recs.append(f"{failed} DR tests failed or aborted — review")
        if not recs:
            recs.append("DR testing healthy — all services compliant")
        return DRTestTrackerReport(
            total_records=total,
            total_analyses=len(self._analyses),
            compliance_rate=rate,
            by_test_type=by_tt,
            by_outcome=by_o,
            by_rto_compliance=by_rto,
            non_compliant_services=non_compliant,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            k = r.test_type.value
            type_dist[k] = type_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "compliance_threshold": self._compliance_threshold,
            "test_type_distribution": type_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("dr_test_tracker_engine.cleared")
        return {"status": "cleared"}

    # -- domain methods ---

    def compute_rto_rpo_gaps(self) -> list[dict[str, Any]]:
        """Compute RTO/RPO target vs actual gaps per service."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            rto_gap = round(r.rto_actual_seconds - r.rto_target_seconds, 2)
            rpo_gap = round(r.rpo_actual_seconds - r.rpo_target_seconds, 2)
            if rto_gap > 0 or rpo_gap > 0:
                results.append(
                    {
                        "service_id": r.service_id,
                        "test_type": r.test_type.value,
                        "rto_gap_seconds": rto_gap,
                        "rpo_gap_seconds": rpo_gap,
                        "data_loss_bytes": r.data_loss_bytes,
                    }
                )
        results.sort(key=lambda x: x["rto_gap_seconds"], reverse=True)
        return results

    def summarize_outcomes_by_test_type(self) -> list[dict[str, Any]]:
        """Summarize pass/fail rates per test type."""
        type_results: dict[str, dict[str, int]] = {}
        for r in self._records:
            k = r.test_type.value
            type_results.setdefault(k, {"success": 0, "fail": 0, "total": 0})
            type_results[k]["total"] += 1
            if r.test_outcome == TestOutcome.SUCCESS:
                type_results[k]["success"] += 1
            elif r.test_outcome in (TestOutcome.FAILED, TestOutcome.ABORTED):
                type_results[k]["fail"] += 1
        results: list[dict[str, Any]] = []
        for ttype, data in type_results.items():
            rate = round(data["success"] / data["total"] * 100, 2) if data["total"] else 0.0
            results.append(
                {
                    "test_type": ttype,
                    "success_rate_pct": rate,
                    "success_count": data["success"],
                    "fail_count": data["fail"],
                    "total_count": data["total"],
                }
            )
        results.sort(key=lambda x: x["success_rate_pct"])
        return results

    def identify_untested_services(
        self,
        known_services: list[str] | None = None,
    ) -> list[str]:
        """Identify services that have not been DR-tested."""
        tested = {r.service_id for r in self._records}
        if known_services is None:
            return []
        return [s for s in known_services if s not in tested]
