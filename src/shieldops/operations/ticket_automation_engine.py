"""TicketAutomationEngine — automate ticket ops."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TicketAction(StrEnum):
    CREATE = "create"
    UPDATE = "update"
    ESCALATE = "escalate"
    CLOSE = "close"
    REOPEN = "reopen"


class RoutingRule(StrEnum):
    SEVERITY_BASED = "severity_based"
    TEAM_BASED = "team_based"
    ROUND_ROBIN = "round_robin"
    SKILL_MATCH = "skill_match"


class ClosureReason(StrEnum):
    RESOLVED = "resolved"
    DUPLICATE = "duplicate"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    AUTO_VERIFIED = "auto_verified"


# --- Models ---


class TicketAutomationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    ticket_action: TicketAction = TicketAction.CREATE
    routing_rule: RoutingRule = RoutingRule.SEVERITY_BASED
    closure_reason: ClosureReason = ClosureReason.RESOLVED
    score: float = 0.0
    ticket_id: str = ""
    assigned_team: str = ""
    finding_id: str = ""
    entity: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class TicketAutomationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    ticket_action: TicketAction = TicketAction.CREATE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TicketAutomationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_ticket_action: dict[str, int] = Field(default_factory=dict)
    by_routing_rule: dict[str, int] = Field(default_factory=dict)
    by_closure_reason: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class TicketAutomationEngine:
    """Automate ticket lifecycle operations."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[TicketAutomationRecord] = []
        self._analyses: list[TicketAutomationAnalysis] = []
        logger.info(
            "ticket_automation_engine.init",
            max_records=max_records,
        )

    def record_item(
        self,
        name: str,
        ticket_action: TicketAction = (TicketAction.CREATE),
        routing_rule: RoutingRule = (RoutingRule.SEVERITY_BASED),
        closure_reason: ClosureReason = (ClosureReason.RESOLVED),
        score: float = 0.0,
        ticket_id: str = "",
        assigned_team: str = "",
        finding_id: str = "",
        entity: str = "",
        service: str = "",
        team: str = "",
    ) -> TicketAutomationRecord:
        record = TicketAutomationRecord(
            name=name,
            ticket_action=ticket_action,
            routing_rule=routing_rule,
            closure_reason=closure_reason,
            score=score,
            ticket_id=ticket_id,
            assigned_team=assigned_team,
            finding_id=finding_id,
            entity=entity,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ticket_automation.item_recorded",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> TicketAutomationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        ticket_action: TicketAction | None = None,
        routing_rule: RoutingRule | None = None,
        limit: int = 50,
    ) -> list[TicketAutomationRecord]:
        results = list(self._records)
        if ticket_action is not None:
            results = [r for r in results if r.ticket_action == ticket_action]
        if routing_rule is not None:
            results = [r for r in results if r.routing_rule == routing_rule]
        return results[-limit:]

    # -- domain methods ---

    def auto_create_ticket(
        self,
    ) -> list[dict[str, Any]]:
        """List auto-created tickets."""
        created = [r for r in self._records if r.ticket_action == TicketAction.CREATE]
        results: list[dict[str, Any]] = []
        for r in created:
            results.append(
                {
                    "ticket_id": r.ticket_id,
                    "name": r.name,
                    "finding_id": r.finding_id,
                    "assigned_team": (r.assigned_team),
                    "routing": (r.routing_rule.value),
                }
            )
        return results

    def route_to_team(
        self,
    ) -> dict[str, Any]:
        """Analyze routing distribution."""
        routing_dist: dict[str, int] = {}
        for r in self._records:
            k = r.routing_rule.value
            routing_dist[k] = routing_dist.get(k, 0) + 1
        team_dist: dict[str, int] = {}
        for r in self._records:
            if r.assigned_team:
                team_dist[r.assigned_team] = team_dist.get(r.assigned_team, 0) + 1
        return {
            "by_routing_rule": routing_dist,
            "by_team": team_dist,
            "total_routed": len(self._records),
        }

    def auto_close_on_verify(
        self,
    ) -> list[dict[str, Any]]:
        """List auto-closed tickets."""
        closed = [
            r
            for r in self._records
            if r.ticket_action == TicketAction.CLOSE
            and r.closure_reason == ClosureReason.AUTO_VERIFIED
        ]
        results: list[dict[str, Any]] = []
        for r in closed:
            results.append(
                {
                    "ticket_id": r.ticket_id,
                    "name": r.name,
                    "reason": (r.closure_reason.value),
                }
            )
        return results

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
    ) -> TicketAutomationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.ticket_action.value] = by_e1.get(r.ticket_action.value, 0) + 1
            by_e2[r.routing_rule.value] = by_e2.get(r.routing_rule.value, 0) + 1
            by_e3[r.closure_reason.value] = by_e3.get(r.closure_reason.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gaps = [r.name for r in self._records if r.score < self._threshold][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Ticket automation is healthy")
        return TicketAutomationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_ticket_action=by_e1,
            by_routing_rule=by_e2,
            by_closure_reason=by_e3,
            top_gaps=gaps,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.ticket_action.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "action_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("ticket_automation_engine.cleared")
        return {"status": "cleared"}
