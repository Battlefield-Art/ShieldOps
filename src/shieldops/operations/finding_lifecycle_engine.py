"""FindingLifecycleEngine — Track finding lifecycle."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class FindingState(StrEnum):
    NEW = "new"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    VERIFIED = "verified"
    CLOSED = "closed"
    REOPENED = "reopened"


class SLACompliance(StrEnum):
    WITHIN_SLA = "within_sla"
    WARNING = "warning"
    BREACHED = "breached"
    NOT_APPLICABLE = "not_applicable"


class VerificationStatus(StrEnum):
    PENDING = "pending"
    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    PARTIAL = "partial"
    SKIPPED = "skipped"


# --- Models ---


class FindingLifecycleRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""
    state: FindingState = FindingState.NEW
    sla: SLACompliance = SLACompliance.WITHIN_SLA
    verification: VerificationStatus = VerificationStatus.PENDING
    score: float = 0.0
    age_days: float = 0.0
    sla_deadline_epoch: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class FindingLifecycleAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""
    state: FindingState = FindingState.NEW
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class FindingLifecycleReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_state: dict[str, int] = Field(default_factory=dict)
    by_sla: dict[str, int] = Field(default_factory=dict)
    by_verification: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class FindingLifecycleEngine:
    """Track security finding lifecycle and SLA."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[FindingLifecycleRecord] = []
        self._analyses: list[FindingLifecycleAnalysis] = []
        logger.info(
            "finding_lifecycle_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def record_item(
        self,
        finding_id: str,
        state: FindingState = FindingState.NEW,
        sla: SLACompliance = (SLACompliance.WITHIN_SLA),
        verification: VerificationStatus = (VerificationStatus.PENDING),
        score: float = 0.0,
        age_days: float = 0.0,
        sla_deadline_epoch: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> FindingLifecycleRecord:
        record = FindingLifecycleRecord(
            finding_id=finding_id,
            state=state,
            sla=sla,
            verification=verification,
            score=score,
            age_days=age_days,
            sla_deadline_epoch=sla_deadline_epoch,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "finding_lifecycle.record_added",
            record_id=record.id,
            finding_id=finding_id,
            state=state.value,
        )
        return record

    def get_record(self, record_id: str) -> FindingLifecycleRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        state: FindingState | None = None,
        sla: SLACompliance | None = None,
        limit: int = 50,
    ) -> list[FindingLifecycleRecord]:
        results = list(self._records)
        if state is not None:
            results = [r for r in results if r.state == state]
        if sla is not None:
            results = [r for r in results if r.sla == sla]
        return results[-limit:]

    # -- domain operations --------------------------------

    def track_finding_lifecycle(self, finding_id: str) -> dict[str, Any]:
        """Track lifecycle of a specific finding."""
        matched = [r for r in self._records if r.finding_id == finding_id]
        if not matched:
            return {
                "finding_id": finding_id,
                "status": "not_found",
            }
        transitions = [
            {
                "state": r.state.value,
                "timestamp": r.created_at,
            }
            for r in matched
        ]
        latest = matched[-1]
        return {
            "finding_id": finding_id,
            "current_state": latest.state.value,
            "sla": latest.sla.value,
            "age_days": latest.age_days,
            "transitions": transitions,
        }

    def measure_sla_compliance(
        self,
    ) -> dict[str, Any]:
        """Measure SLA compliance across findings."""
        total = len(self._records)
        if total == 0:
            return {"compliance_rate": 0.0}
        within = sum(1 for r in self._records if r.sla == SLACompliance.WITHIN_SLA)
        breached = sum(1 for r in self._records if r.sla == SLACompliance.BREACHED)
        return {
            "total": total,
            "within_sla": within,
            "breached": breached,
            "compliance_rate": round(within / total, 3),
            "breach_rate": round(breached / total, 3),
        }

    def verify_remediation(
        self,
    ) -> list[dict[str, Any]]:
        """List findings needing verification."""
        pending = [
            r
            for r in self._records
            if r.state == FindingState.REMEDIATED and r.verification == VerificationStatus.PENDING
        ]
        results: list[dict[str, Any]] = []
        for r in pending:
            results.append(
                {
                    "finding_id": r.finding_id,
                    "service": r.service,
                    "team": r.team,
                    "age_days": r.age_days,
                    "sla": r.sla.value,
                }
            )
        return sorted(
            results,
            key=lambda x: x["age_days"],
            reverse=True,
        )

    # -- standard methods ---------------------------------

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.finding_id == key or r.service == key]
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
    ) -> FindingLifecycleReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.state.value] = by_e1.get(r.state.value, 0) + 1
            by_e2[r.sla.value] = by_e2.get(r.sla.value, 0) + 1
            by_e3[r.verification.value] = by_e3.get(r.verification.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_ct = sum(1 for r in self._records if r.score < self._threshold)
        recs: list[str] = []
        if gap_ct > 0:
            recs.append(f"{gap_ct} finding(s) below threshold")
        if not recs:
            recs.append("Finding lifecycle engine healthy")
        return FindingLifecycleReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_ct,
            avg_score=avg,
            by_state=by_e1,
            by_sla=by_e2,
            by_verification=by_e3,
            top_gaps=[],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.state.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "state_distribution": dist,
            "unique_services": len({r.service for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("finding_lifecycle_engine.cleared")
        return {"status": "cleared"}
