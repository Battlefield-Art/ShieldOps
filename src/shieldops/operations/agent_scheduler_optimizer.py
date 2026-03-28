"""Agent Scheduler Optimizer — detect conflicts and balance load."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ScheduleConflict(StrEnum):
    NONE = "none"
    OVERLAP = "overlap"
    RESOURCE = "resource"
    DEPENDENCY = "dependency"


class LoadBalance(StrEnum):
    BALANCED = "balanced"
    SKEWED = "skewed"
    OVERLOADED = "overloaded"
    IDLE = "idle"


class PriorityQueue(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# --- Models ---


class SchedulerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = ""
    conflict: ScheduleConflict = ScheduleConflict.NONE
    load: LoadBalance = LoadBalance.BALANCED
    priority: PriorityQueue = PriorityQueue.MEDIUM
    score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class SchedulerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = ""
    conflict: ScheduleConflict = ScheduleConflict.NONE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SchedulerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_score: float = 0.0
    by_conflict: dict[str, int] = Field(default_factory=dict)
    by_load: dict[str, int] = Field(default_factory=dict)
    by_priority: dict[str, int] = Field(default_factory=dict)
    overloaded_agents: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentSchedulerOptimizer:
    """Optimize agent scheduling and load balance."""

    def __init__(
        self,
        max_records: int = 200000,
        load_threshold: float = 80.0,
    ) -> None:
        self._max = max_records
        self._load_threshold = load_threshold
        self._records: list[SchedulerRecord] = []
        self._analyses: list[SchedulerAnalysis] = []
        logger.info(
            "agent_scheduler_optimizer.initialized",
            max_records=max_records,
        )

    def record_item(
        self,
        agent_name: str = "",
        conflict: ScheduleConflict = (ScheduleConflict.NONE),
        load: LoadBalance = LoadBalance.BALANCED,
        priority: PriorityQueue = PriorityQueue.MEDIUM,
        score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> SchedulerRecord:
        rec = SchedulerRecord(
            agent_name=agent_name,
            conflict=conflict,
            load=load,
            priority=priority,
            score=score,
            service=service,
            team=team,
        )
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "agent_scheduler.item_recorded",
            record_id=rec.id,
        )
        return rec

    def process(self, key: str) -> SchedulerAnalysis:
        matches = [r for r in self._records if r.agent_name == key]
        total = sum(r.score for r in matches)
        avg = total / len(matches) if matches else 0.0
        analysis = SchedulerAnalysis(
            agent_name=key,
            analysis_score=round(avg, 2),
            threshold=self._load_threshold,
            breached=avg > self._load_threshold,
            description=(f"Analyzed {len(matches)} schedules"),
        )
        self._analyses.append(analysis)
        return analysis

    # -- domain methods ---

    def detect_conflicts(
        self,
    ) -> list[dict[str, Any]]:
        """Find records with scheduling conflicts."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.conflict != ScheduleConflict.NONE:
                results.append(
                    {
                        "id": r.id,
                        "agent": r.agent_name,
                        "conflict": r.conflict.value,
                        "score": r.score,
                    }
                )
        return results

    def balance_load(self) -> dict[str, Any]:
        """Aggregate load balance across agents."""
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.load.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "distribution": dist,
            "total": len(self._records),
        }

    def optimize_priority(
        self,
    ) -> list[dict[str, Any]]:
        """Rank agents by priority and score."""
        priority_order = {
            PriorityQueue.CRITICAL: 0,
            PriorityQueue.HIGH: 1,
            PriorityQueue.MEDIUM: 2,
            PriorityQueue.LOW: 3,
        }
        ranked = sorted(
            self._records,
            key=lambda r: (
                priority_order.get(r.priority, 9),
                -r.score,
            ),
        )
        return [
            {
                "agent": r.agent_name,
                "priority": r.priority.value,
                "score": r.score,
            }
            for r in ranked[:20]
        ]

    # -- report / stats ---

    def generate_report(self) -> SchedulerReport:
        by_conflict: dict[str, int] = {}
        by_load: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        for r in self._records:
            c = r.conflict.value
            by_conflict[c] = by_conflict.get(c, 0) + 1
            ld = r.load.value
            by_load[ld] = by_load.get(ld, 0) + 1
            p = r.priority.value
            by_priority[p] = by_priority.get(p, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        overloaded = [r.agent_name for r in self._records if r.load == LoadBalance.OVERLOADED][:5]
        recs: list[str] = []
        if overloaded:
            recs.append(f"{len(overloaded)} agent(s) overloaded")
        if not recs:
            recs.append("Schedule is balanced")
        return SchedulerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_score=avg,
            by_conflict=by_conflict,
            by_load=by_load,
            by_priority=by_priority,
            overloaded_agents=overloaded,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.load.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "load_threshold": self._load_threshold,
            "load_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_scheduler_optimizer.cleared")
        return {"status": "cleared"}
