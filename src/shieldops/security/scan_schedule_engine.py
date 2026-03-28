"""ScanScheduleEngine — manage scan schedules."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ScheduleType(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    ON_DEMAND = "on_demand"


class ComplianceDriver(StrEnum):
    PCI_DSS = "pci_dss"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    NIST = "nist"
    INTERNAL = "internal"


class OverdueStatus(StrEnum):
    ON_TIME = "on_time"
    WARNING = "warning"
    OVERDUE = "overdue"
    CRITICAL = "critical"


# --- Models ---


class ScanScheduleRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    schedule_type: ScheduleType = ScheduleType.WEEKLY
    compliance_driver: ComplianceDriver = ComplianceDriver.INTERNAL
    overdue_status: OverdueStatus = OverdueStatus.ON_TIME
    score: float = 0.0
    last_scan_at: float = 0.0
    next_scan_at: float = 0.0
    interval_hours: int = 168
    entity: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ScanScheduleAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    schedule_type: ScheduleType = ScheduleType.WEEKLY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ScanScheduleReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_schedule_type: dict[str, int] = Field(default_factory=dict)
    by_compliance_driver: dict[str, int] = Field(default_factory=dict)
    by_overdue_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ScanScheduleEngine:
    """Manage and enforce scan schedules."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[ScanScheduleRecord] = []
        self._analyses: list[ScanScheduleAnalysis] = []
        logger.info(
            "scan_schedule_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        name: str,
        schedule_type: ScheduleType = (ScheduleType.WEEKLY),
        compliance_driver: ComplianceDriver = (ComplianceDriver.INTERNAL),
        overdue_status: OverdueStatus = (OverdueStatus.ON_TIME),
        score: float = 0.0,
        last_scan_at: float = 0.0,
        next_scan_at: float = 0.0,
        interval_hours: int = 168,
        entity: str = "",
        service: str = "",
        team: str = "",
    ) -> ScanScheduleRecord:
        record = ScanScheduleRecord(
            name=name,
            schedule_type=schedule_type,
            compliance_driver=compliance_driver,
            overdue_status=overdue_status,
            score=score,
            last_scan_at=last_scan_at,
            next_scan_at=next_scan_at,
            interval_hours=interval_hours,
            entity=entity,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "scan_schedule.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> ScanScheduleRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        schedule_type: ScheduleType | None = None,
        overdue_status: OverdueStatus | None = None,
        limit: int = 50,
    ) -> list[ScanScheduleRecord]:
        results = list(self._records)
        if schedule_type is not None:
            results = [r for r in results if r.schedule_type == schedule_type]
        if overdue_status is not None:
            results = [r for r in results if r.overdue_status == overdue_status]
        return results[-limit:]

    # -- domain methods ---

    def calculate_next_scan(
        self,
    ) -> list[dict[str, Any]]:
        """Calculate next scan time per target."""
        results: list[dict[str, Any]] = []
        now = time.time()
        for r in self._records:
            next_t = r.last_scan_at + r.interval_hours * 3600
            hours_until = round((next_t - now) / 3600, 1)
            results.append(
                {
                    "name": r.name,
                    "service": r.service,
                    "schedule": (r.schedule_type.value),
                    "next_scan_at": next_t,
                    "hours_until": hours_until,
                    "overdue": hours_until < 0,
                }
            )
        return sorted(results, key=lambda x: x["hours_until"])

    def check_compliance_schedule(
        self,
    ) -> list[dict[str, Any]]:
        """Check compliance-driven schedules."""
        driver_data: dict[str, list[ScanScheduleRecord]] = {}
        for r in self._records:
            driver_data.setdefault(r.compliance_driver.value, []).append(r)
        results: list[dict[str, Any]] = []
        for driver, recs in driver_data.items():
            on_time = sum(1 for r in recs if r.overdue_status == OverdueStatus.ON_TIME)
            results.append(
                {
                    "driver": driver,
                    "total": len(recs),
                    "on_time": on_time,
                    "compliance_pct": round(
                        on_time / len(recs) * 100,
                        1,
                    ),
                }
            )
        return sorted(
            results,
            key=lambda x: x["compliance_pct"],
        )

    def detect_overdue(
        self,
    ) -> list[dict[str, Any]]:
        """Detect overdue scans."""
        overdue: list[dict[str, Any]] = []
        for r in self._records:
            if r.overdue_status in (
                OverdueStatus.OVERDUE,
                OverdueStatus.CRITICAL,
            ):
                overdue.append(
                    {
                        "name": r.name,
                        "service": r.service,
                        "status": (r.overdue_status.value),
                        "driver": (r.compliance_driver.value),
                        "last_scan": (r.last_scan_at),
                    }
                )
        return sorted(
            overdue,
            key=lambda x: x["last_scan"],
        )

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
        }

    def generate_report(
        self,
    ) -> ScanScheduleReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.schedule_type.value] = by_e1.get(r.schedule_type.value, 0) + 1
            by_e2[r.compliance_driver.value] = by_e2.get(r.compliance_driver.value, 0) + 1
            by_e3[r.overdue_status.value] = by_e3.get(r.overdue_status.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gaps = [r.name for r in self._records if r.score < self._threshold][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Scan schedule is healthy")
        return ScanScheduleReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_schedule_type=by_e1,
            by_compliance_driver=by_e2,
            by_overdue_status=by_e3,
            top_gaps=gaps,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.schedule_type.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "schedule_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("scan_schedule_engine.cleared")
        return {"status": "cleared"}
