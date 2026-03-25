"""Triage Routing Optimizer Engine — optimize incident routing to teams."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RoutingStrategy(StrEnum):
    SKILL_BASED = "skill_based"
    LOAD_BALANCED = "load_balanced"
    ROUND_ROBIN = "round_robin"
    ESCALATION = "escalation"
    AI_RECOMMENDED = "ai_recommended"


class RoutingOutcome(StrEnum):
    CORRECT_FIRST_TIME = "correct_first_time"
    REROUTED = "rerouted"
    ESCALATED = "escalated"
    BOUNCED = "bounced"
    TIMEOUT = "timeout"


class TeamLoad(StrEnum):
    UNDER = "under"
    OPTIMAL = "optimal"
    HEAVY = "heavy"
    OVERLOADED = "overloaded"
    UNAVAILABLE = "unavailable"


# --- Models ---


class TriageRoutingRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    routing_strategy: RoutingStrategy = RoutingStrategy.SKILL_BASED
    routing_outcome: RoutingOutcome = RoutingOutcome.CORRECT_FIRST_TIME
    team_load: TeamLoad = TeamLoad.OPTIMAL
    assigned_team: str = ""
    reroute_count: int = 0
    time_to_assign_ms: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class TriageRoutingAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    routing_strategy: RoutingStrategy = RoutingStrategy.SKILL_BASED
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TriageRoutingReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_routing_strategy: dict[str, int] = Field(default_factory=dict)
    by_routing_outcome: dict[str, int] = Field(default_factory=dict)
    by_team_load: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class TriageRoutingOptimizerEngine:
    """Triage Routing Optimizer Engine — optimize incident routing to teams."""

    def __init__(
        self,
        max_records: int = 200000,
        efficiency_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = efficiency_threshold
        self._records: list[TriageRoutingRecord] = []
        self._analyses: list[TriageRoutingAnalysis] = []
        logger.info(
            "triage_routing_optimizer_engine.initialized",
            max_records=max_records,
            efficiency_threshold=efficiency_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        incident_id: str,
        routing_strategy: RoutingStrategy = RoutingStrategy.SKILL_BASED,
        routing_outcome: RoutingOutcome = RoutingOutcome.CORRECT_FIRST_TIME,
        team_load: TeamLoad = TeamLoad.OPTIMAL,
        assigned_team: str = "",
        reroute_count: int = 0,
        time_to_assign_ms: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> TriageRoutingRecord:
        record = TriageRoutingRecord(
            incident_id=incident_id,
            routing_strategy=routing_strategy,
            routing_outcome=routing_outcome,
            team_load=team_load,
            assigned_team=assigned_team,
            reroute_count=reroute_count,
            time_to_assign_ms=time_to_assign_ms,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "triage_routing_optimizer_engine.record_added",
            record_id=record.id,
            incident_id=incident_id,
            routing_strategy=routing_strategy.value,
            routing_outcome=routing_outcome.value,
        )
        return record

    def get_record(self, record_id: str) -> TriageRoutingRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        routing_strategy: RoutingStrategy | None = None,
        routing_outcome: RoutingOutcome | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[TriageRoutingRecord]:
        results = list(self._records)
        if routing_strategy is not None:
            results = [r for r in results if r.routing_strategy == routing_strategy]
        if routing_outcome is not None:
            results = [r for r in results if r.routing_outcome == routing_outcome]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        routing_strategy: RoutingStrategy = RoutingStrategy.SKILL_BASED,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> TriageRoutingAnalysis:
        analysis = TriageRoutingAnalysis(
            name=name,
            routing_strategy=routing_strategy,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "triage_routing_optimizer_engine.analysis_added",
            name=name,
            routing_strategy=routing_strategy.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_routing_efficiency(self) -> dict[str, Any]:
        strategy_data: dict[str, list[str]] = {}
        for r in self._records:
            key = r.routing_strategy.value
            strategy_data.setdefault(key, []).append(r.routing_outcome.value)
        result: dict[str, Any] = {}
        for k, outcomes in strategy_data.items():
            correct = sum(1 for o in outcomes if o == "correct_first_time")
            result[k] = {
                "count": len(outcomes),
                "first_time_pct": round(correct / len(outcomes) * 100, 2),
            }
        return result

    def identify_bounce_patterns(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.routing_outcome in (RoutingOutcome.BOUNCED, RoutingOutcome.TIMEOUT):
                results.append(
                    {
                        "record_id": r.id,
                        "incident_id": r.incident_id,
                        "routing_strategy": r.routing_strategy.value,
                        "routing_outcome": r.routing_outcome.value,
                        "assigned_team": r.assigned_team,
                        "reroute_count": r.reroute_count,
                        "time_to_assign_ms": r.time_to_assign_ms,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["reroute_count"], reverse=True)

    def detect_routing_trends(self) -> dict[str, Any]:
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

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> TriageRoutingReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.routing_strategy.value] = by_e1.get(r.routing_strategy.value, 0) + 1
            by_e2[r.routing_outcome.value] = by_e2.get(r.routing_outcome.value, 0) + 1
            by_e3[r.team_load.value] = by_e3.get(r.team_load.value, 0) + 1
        correct_count = sum(
            1 for r in self._records if r.routing_outcome == RoutingOutcome.CORRECT_FIRST_TIME
        )
        efficiency_pct = (
            round(correct_count / len(self._records) * 100, 2) if self._records else 0.0
        )
        gap_count = sum(
            1
            for r in self._records
            if r.routing_outcome in (RoutingOutcome.BOUNCED, RoutingOutcome.TIMEOUT)
        )
        gap_list = self.identify_bounce_patterns()
        top_gaps = [g["incident_id"] for g in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} bounced/timed-out routing(s)")
        if self._records and efficiency_pct < self._threshold:
            recs.append(
                f"First-time routing {efficiency_pct}% below threshold ({self._threshold}%)"
            )
        if not recs:
            recs.append("Triage Routing Optimizer Engine is healthy")
        return TriageRoutingReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=efficiency_pct,
            by_routing_strategy=by_e1,
            by_routing_outcome=by_e2,
            by_team_load=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("triage_routing_optimizer_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.routing_strategy.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "efficiency_threshold": self._threshold,
            "routing_strategy_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
