"""DistributedContextEngine — track and analyze distributed context propagation."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ContextType(StrEnum):
    W3C_TRACEPARENT = "w3c_traceparent"
    B3_PROPAGATION = "b3_propagation"
    BAGGAGE = "baggage"
    CUSTOM_HEADER = "custom_header"


class PropagationStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    BROKEN = "broken"
    MISSING = "missing"


class ContextIssue(StrEnum):
    MISSING_PARENT = "missing_parent"
    ORPHAN_SPAN = "orphan_span"
    CONTEXT_LEAK = "context_leak"
    HEADER_CORRUPTION = "header_corruption"


# --- Models ---


class DistributedContextRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    context_type: ContextType = ContextType.W3C_TRACEPARENT
    propagation_status: PropagationStatus = PropagationStatus.COMPLETE
    context_issue: ContextIssue = ContextIssue.MISSING_PARENT
    score: float = 0.0
    baggage_item_count: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class DistributedContextAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    context_type: ContextType = ContextType.W3C_TRACEPARENT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DistributedContextReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_context_type: dict[str, int] = Field(default_factory=dict)
    by_propagation_status: dict[str, int] = Field(default_factory=dict)
    by_context_issue: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class DistributedContextEngine:
    """Distributed Context Engine — track context propagation across services."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[DistributedContextRecord] = []
        self._analyses: list[DistributedContextAnalysis] = []
        logger.info(
            "distributed_context_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        context_type: ContextType = ContextType.W3C_TRACEPARENT,
        propagation_status: PropagationStatus = PropagationStatus.COMPLETE,
        context_issue: ContextIssue = ContextIssue.MISSING_PARENT,
        score: float = 0.0,
        baggage_item_count: int = 0,
        service: str = "",
        team: str = "",
    ) -> DistributedContextRecord:
        record = DistributedContextRecord(
            name=name,
            context_type=context_type,
            propagation_status=propagation_status,
            context_issue=context_issue,
            score=score,
            baggage_item_count=baggage_item_count,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "distributed_context_engine.record_added",
            record_id=record.id,
            name=name,
            context_type=context_type.value,
            propagation_status=propagation_status.value,
        )
        return record

    def get_record(self, record_id: str) -> DistributedContextRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        context_type: ContextType | None = None,
        propagation_status: PropagationStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[DistributedContextRecord]:
        results = list(self._records)
        if context_type is not None:
            results = [r for r in results if r.context_type == context_type]
        if propagation_status is not None:
            results = [r for r in results if r.propagation_status == propagation_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        context_type: ContextType = ContextType.W3C_TRACEPARENT,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> DistributedContextAnalysis:
        analysis = DistributedContextAnalysis(
            name=name,
            context_type=context_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "distributed_context_engine.analysis_added",
            name=name,
            context_type=context_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.context_type.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
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
                        "context_type": r.context_type.value,
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

    def detect_trends(self) -> dict[str, Any]:
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [a.analysis_score for a in self._analyses]
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

    def detect_broken_propagation(self) -> list[dict[str, Any]]:
        """Find services that break context propagation chains."""
        svc_data: dict[str, list[DistributedContextRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            broken = [
                r
                for r in records
                if r.propagation_status in (PropagationStatus.BROKEN, PropagationStatus.MISSING)
            ]
            if broken:
                issue_counts: dict[str, int] = {}
                for r in broken:
                    issue_counts[r.context_issue.value] = (
                        issue_counts.get(r.context_issue.value, 0) + 1
                    )
                results.append(
                    {
                        "service": svc,
                        "broken_count": len(broken),
                        "total_count": len(records),
                        "break_rate": round(len(broken) / len(records) * 100, 2),
                        "issue_breakdown": issue_counts,
                    }
                )
        return sorted(results, key=lambda x: x["break_rate"], reverse=True)

    def measure_propagation_coverage(self) -> dict[str, Any]:
        """Measure percentage of requests with complete context propagation."""
        if not self._records:
            return {
                "total_requests": 0,
                "complete_pct": 0.0,
                "partial_pct": 0.0,
                "broken_pct": 0.0,
                "missing_pct": 0.0,
            }
        status_counts: dict[str, int] = {}
        for r in self._records:
            status_counts[r.propagation_status.value] = (
                status_counts.get(r.propagation_status.value, 0) + 1
            )
        total = len(self._records)
        return {
            "total_requests": total,
            "complete_pct": round(status_counts.get("complete", 0) / total * 100, 2),
            "partial_pct": round(status_counts.get("partial", 0) / total * 100, 2),
            "broken_pct": round(status_counts.get("broken", 0) / total * 100, 2),
            "missing_pct": round(status_counts.get("missing", 0) / total * 100, 2),
        }

    def identify_context_leaks(
        self,
        baggage_threshold: int = 10,
    ) -> list[dict[str, Any]]:
        """Find services leaking sensitive baggage items."""
        svc_data: dict[str, list[DistributedContextRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        leaks: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            leak_records = [
                r
                for r in records
                if r.context_issue == ContextIssue.CONTEXT_LEAK
                or r.baggage_item_count > baggage_threshold
            ]
            if leak_records:
                max_baggage = max(r.baggage_item_count for r in leak_records)
                avg_baggage = round(
                    sum(r.baggage_item_count for r in leak_records) / len(leak_records), 2
                )
                leaks.append(
                    {
                        "service": svc,
                        "leak_count": len(leak_records),
                        "max_baggage_items": max_baggage,
                        "avg_baggage_items": avg_baggage,
                        "severity": (
                            "critical" if max_baggage > baggage_threshold * 3 else "warning"
                        ),
                    }
                )
        return sorted(leaks, key=lambda x: x["max_baggage_items"], reverse=True)

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> DistributedContextReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.context_type.value] = by_e1.get(r.context_type.value, 0) + 1
            by_e2[r.propagation_status.value] = by_e2.get(r.propagation_status.value, 0) + 1
            by_e3[r.context_issue.value] = by_e3.get(r.context_issue.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Distributed Context Engine is healthy")
        return DistributedContextReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_context_type=by_e1,
            by_propagation_status=by_e2,
            by_context_issue=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("distributed_context_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.context_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "context_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
