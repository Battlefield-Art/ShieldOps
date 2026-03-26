"""ApprovalGateTrackerEngine — Track and analyze approval gate decisions."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class GateType(StrEnum):
    MANUAL_APPROVAL = "manual_approval"
    POLICY_CHECK = "policy_check"
    SLO_GUARD = "slo_guard"
    CHANGE_WINDOW = "change_window"
    BLAST_RADIUS = "blast_radius"


class ApprovalOutcome(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    AUTO_APPROVED = "auto_approved"
    ESCALATED = "escalated"


class WaitCategory(StrEnum):
    UNDER_1H = "under_1h"
    UNDER_4H = "under_4h"
    UNDER_24H = "under_24h"
    OVER_24H = "over_24h"
    INSTANT = "instant"


# --- Models ---


class ApprovalGateTrackerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    gate_type: GateType = GateType.MANUAL_APPROVAL
    approval_outcome: ApprovalOutcome = ApprovalOutcome.APPROVED
    wait_category: WaitCategory = WaitCategory.INSTANT
    score: float = 0.0
    wait_seconds: float = 0.0
    approver: str = ""
    requester: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ApprovalGateTrackerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    gate_type: GateType = GateType.MANUAL_APPROVAL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ApprovalGateTrackerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_gate_type: dict[str, int] = Field(default_factory=dict)
    by_approval_outcome: dict[str, int] = Field(default_factory=dict)
    by_wait_category: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ApprovalGateTrackerEngine:
    """Track and analyze approval gate decisions and wait times."""

    def __init__(
        self,
        max_records: int = 200000,
        approval_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = approval_threshold
        self._records: list[ApprovalGateTrackerRecord] = []
        self._analyses: list[ApprovalGateTrackerAnalysis] = []
        logger.info(
            "approval_gate_tracker_engine.initialized",
            max_records=max_records,
            approval_threshold=approval_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        gate_type: GateType = GateType.MANUAL_APPROVAL,
        approval_outcome: ApprovalOutcome = ApprovalOutcome.APPROVED,
        wait_category: WaitCategory = WaitCategory.INSTANT,
        score: float = 0.0,
        wait_seconds: float = 0.0,
        approver: str = "",
        requester: str = "",
        service: str = "",
        team: str = "",
    ) -> ApprovalGateTrackerRecord:
        record = ApprovalGateTrackerRecord(
            name=name,
            gate_type=gate_type,
            approval_outcome=approval_outcome,
            wait_category=wait_category,
            score=score,
            wait_seconds=wait_seconds,
            approver=approver,
            requester=requester,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "approval_gate_tracker_engine.record_added",
            record_id=record.id,
            name=name,
            gate_type=gate_type.value,
            approval_outcome=approval_outcome.value,
        )
        return record

    def get_record(self, record_id: str) -> ApprovalGateTrackerRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        gate_type: GateType | None = None,
        approval_outcome: ApprovalOutcome | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ApprovalGateTrackerRecord]:
        results = list(self._records)
        if gate_type is not None:
            results = [r for r in results if r.gate_type == gate_type]
        if approval_outcome is not None:
            results = [
                r for r in results if r.approval_outcome == approval_outcome
            ]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        gate_type: GateType = GateType.MANUAL_APPROVAL,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ApprovalGateTrackerAnalysis:
        analysis = ApprovalGateTrackerAnalysis(
            name=name,
            gate_type=gate_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "approval_gate_tracker_engine.analysis_added",
            name=name,
            gate_type=gate_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_bottleneck_gates(self) -> list[dict[str, Any]]:
        """Identify gates that cause the most delays."""
        gate_waits: dict[str, list[float]] = {}
        for r in self._records:
            g = r.gate_type.value
            gate_waits.setdefault(g, []).append(r.wait_seconds)
        bottlenecks: list[dict[str, Any]] = []
        for gate, waits in gate_waits.items():
            avg_wait = round(sum(waits) / len(waits), 2) if waits else 0.0
            max_wait = max(waits) if waits else 0.0
            over_1h = sum(1 for w in waits if w > 3600)
            bottlenecks.append(
                {
                    "gate_type": gate,
                    "total_requests": len(waits),
                    "avg_wait_seconds": avg_wait,
                    "max_wait_seconds": max_wait,
                    "over_1h_count": over_1h,
                    "severity": "critical" if avg_wait > 3600 else "warning",
                }
            )
        return sorted(
            bottlenecks, key=lambda x: x["avg_wait_seconds"], reverse=True
        )

    def compute_approval_rates(self) -> list[dict[str, Any]]:
        """Compute approval rates per gate type."""
        gate_records: dict[str, list[ApprovalGateTrackerRecord]] = {}
        for r in self._records:
            gate_records.setdefault(r.gate_type.value, []).append(r)
        results: list[dict[str, Any]] = []
        for gate, records in gate_records.items():
            total = len(records)
            approved = sum(
                1
                for r in records
                if r.approval_outcome
                in (ApprovalOutcome.APPROVED, ApprovalOutcome.AUTO_APPROVED)
            )
            rate = round(approved / total * 100, 1) if total else 0.0
            avg_wait = (
                round(
                    sum(r.wait_seconds for r in records) / total, 2
                )
                if total
                else 0.0
            )
            results.append(
                {
                    "gate_type": gate,
                    "total_requests": total,
                    "approved": approved,
                    "approval_rate_pct": rate,
                    "avg_wait_seconds": avg_wait,
                }
            )
        return sorted(results, key=lambda x: x["approval_rate_pct"])

    def recommend_gate_optimizations(self) -> list[dict[str, Any]]:
        """Recommend gate optimizations based on wait patterns."""
        recommendations: list[dict[str, Any]] = []
        timeouts = [
            r
            for r in self._records
            if r.approval_outcome == ApprovalOutcome.TIMEOUT
        ]
        for r in timeouts:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "gate_type": r.gate_type.value,
                    "issue": "approval_timeout",
                    "priority": "critical",
                    "suggestion": (
                        f"Gate '{r.gate_type.value}' timed out after "
                        f"{r.wait_seconds}s — consider auto-approval policy"
                    ),
                }
            )
        long_waits = [
            r
            for r in self._records
            if r.wait_category
            in (WaitCategory.OVER_24H, WaitCategory.UNDER_24H)
        ]
        for r in long_waits:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "gate_type": r.gate_type.value,
                    "issue": "long_wait",
                    "priority": "high",
                    "suggestion": (
                        f"Reduce wait time ({r.wait_seconds}s) — "
                        f"add auto-approval for low-risk changes"
                    ),
                }
            )
        denied = [
            r
            for r in self._records
            if r.approval_outcome == ApprovalOutcome.DENIED
        ]
        for r in denied:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "gate_type": r.gate_type.value,
                    "issue": "denied",
                    "priority": "medium",
                    "suggestion": "Review denial patterns for improvement",
                }
            )
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        return sorted(
            recommendations, key=lambda x: priority_order.get(x["priority"], 3)
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        gate_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.gate_type.value
            gate_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in gate_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "gate_type": r.gate_type.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [
            r for r in self._records if r.name == key or r.service == key
        ]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(
                1 for s in scores if s < self._threshold
            ),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> ApprovalGateTrackerReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.gate_type.value] = by_e1.get(r.gate_type.value, 0) + 1
            by_e2[r.approval_outcome.value] = (
                by_e2.get(r.approval_outcome.value, 0) + 1
            )
            by_e3[r.wait_category.value] = (
                by_e3.get(r.wait_category.value, 0) + 1
            )
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(
                f"{gap_count} item(s) below threshold ({self._threshold})"
            )
        if self._records and avg_score < self._threshold:
            recs.append(
                f"Avg score {avg_score} below threshold ({self._threshold})"
            )
        if not recs:
            recs.append("Approval Gate Tracker Engine is healthy")
        return ApprovalGateTrackerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_gate_type=by_e1,
            by_approval_outcome=by_e2,
            by_wait_category=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("approval_gate_tracker_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.gate_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "gate_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
