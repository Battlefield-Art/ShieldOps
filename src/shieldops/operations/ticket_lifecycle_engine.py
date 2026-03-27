"""Ticket Lifecycle Engine — track ticket flow."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TicketState(StrEnum):
    OPEN = "open"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    RESOLVED = "resolved"
    CLOSED = "closed"


class AssignmentMethod(StrEnum):
    MANUAL = "manual"
    ROUND_ROBIN = "round_robin"
    SKILL_BASED = "skill_based"
    LOAD_BALANCED = "load_balanced"
    AUTO_AI = "auto_ai"


class ResolutionType(StrEnum):
    FIXED = "fixed"
    WORKAROUND = "workaround"
    DUPLICATE = "duplicate"
    WONT_FIX = "wont_fix"
    FALSE_POSITIVE = "false_positive"


# --- Models ---


class TicketRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ticket_id: str = ""
    state: TicketState = TicketState.OPEN
    assignment: AssignmentMethod = AssignmentMethod.MANUAL
    resolution: str = ""
    assignee: str = ""
    priority: str = "medium"
    duration_sec: float = 0.0
    created_at: float = Field(default_factory=time.time)


class TicketAnalysis(BaseModel):
    ticket_id: str = ""
    state_transitions: int = 0
    total_duration_sec: float = 0.0
    was_blocked: bool = False
    resolution: str = ""
    analyzed_at: float = Field(default_factory=time.time)


class TicketReport(BaseModel):
    total_tickets: int = 0
    avg_resolution_sec: float = 0.0
    by_state: dict[str, int] = Field(default_factory=dict)
    by_resolution: dict[str, int] = Field(default_factory=dict)
    blocked_count: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class TicketLifecycleEngine:
    """Track ticket lifecycle and routing."""

    def __init__(self, max_records: int = 10000) -> None:
        self._max = max_records
        self._records: list[TicketRecord] = []
        logger.info(
            "ticket_lifecycle_engine.init",
            max_records=max_records,
        )

    def record_item(self, **kwargs: Any) -> TicketRecord:
        rec = TicketRecord(**kwargs)
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "ticket_lifecycle.recorded",
            record_id=rec.id,
        )
        return rec

    def process(self, ticket_id: str) -> TicketAnalysis:
        recs = [r for r in self._records if r.ticket_id == ticket_id]
        if not recs:
            return TicketAnalysis(ticket_id=ticket_id)
        total_dur = sum(r.duration_sec for r in recs)
        blocked = any(r.state == TicketState.BLOCKED for r in recs)
        res = recs[-1].resolution or ""
        return TicketAnalysis(
            ticket_id=ticket_id,
            state_transitions=len(recs),
            total_duration_sec=round(total_dur, 2),
            was_blocked=blocked,
            resolution=res,
        )

    def generate_report(self) -> TicketReport:
        by_state: dict[str, int] = {}
        by_res: dict[str, int] = {}
        for r in self._records:
            s = r.state.value
            by_state[s] = by_state.get(s, 0) + 1
            if r.resolution:
                by_res[r.resolution] = by_res.get(r.resolution, 0) + 1
        total = len(self._records)
        durations = [r.duration_sec for r in self._records if r.duration_sec > 0]
        avg_dur = round(sum(durations) / len(durations), 2) if durations else 0.0
        blocked = sum(1 for r in self._records if r.state == TicketState.BLOCKED)
        recs: list[str] = []
        if blocked > 0:
            recs.append(f"{blocked} blocked ticket(s)")
        if avg_dur > 86400:
            recs.append("Avg resolution exceeds 24h")
        if not recs:
            recs.append("Ticket flow healthy")
        return TicketReport(
            total_tickets=total,
            avg_resolution_sec=avg_dur,
            by_state=by_state,
            by_resolution=by_res,
            blocked_count=blocked,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max,
            "unique_tickets": len({r.ticket_id for r in self._records}),
        }

    def clear_data(self) -> None:
        self._records.clear()
        logger.info("ticket_lifecycle.cleared")

    # -- domain methods --

    def track_ticket(
        self,
        ticket_id: str,
        state: TicketState,
        assignee: str = "",
        priority: str = "medium",
        duration_sec: float = 0.0,
        assignment: AssignmentMethod = (AssignmentMethod.MANUAL),
    ) -> TicketRecord:
        """Record a ticket state transition."""
        return self.record_item(
            ticket_id=ticket_id,
            state=state,
            assignee=assignee,
            priority=priority,
            duration_sec=duration_sec,
            assignment=assignment,
        )

    def measure_resolution_time(
        self,
        priority: str | None = None,
    ) -> dict[str, Any]:
        """Measure avg resolution time."""
        recs = self._records
        if priority:
            recs = [r for r in recs if r.priority == priority]
        resolved = [
            r
            for r in recs
            if r.state
            in (
                TicketState.RESOLVED,
                TicketState.CLOSED,
            )
        ]
        durations = [r.duration_sec for r in resolved if r.duration_sec > 0]
        avg = round(sum(durations) / len(durations), 2) if durations else 0.0
        return {
            "priority": priority or "all",
            "resolved_count": len(resolved),
            "avg_resolution_sec": avg,
        }

    def optimize_routing(
        self,
    ) -> list[dict[str, Any]]:
        """Suggest routing optimizations."""
        by_method: dict[str, list[float]] = {}
        for r in self._records:
            m = r.assignment.value
            by_method.setdefault(m, [])
            if r.duration_sec > 0:
                by_method[m].append(r.duration_sec)
        results: list[dict[str, Any]] = []
        for method, durs in by_method.items():
            avg = round(sum(durs) / len(durs), 2) if durs else 0.0
            results.append(
                {
                    "method": method,
                    "ticket_count": len(durs),
                    "avg_duration_sec": avg,
                }
            )
        results.sort(key=lambda x: x["avg_duration_sec"])
        return results
