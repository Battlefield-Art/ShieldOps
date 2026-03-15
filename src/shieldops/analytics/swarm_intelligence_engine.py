"""Swarm Intelligence Engine —
analyze multi-agent swarm coordination, identify bottleneck agents,
and optimize task distribution across agent clusters."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SwarmRole(StrEnum):
    LEADER = "leader"
    WORKER = "worker"
    OBSERVER = "observer"
    COORDINATOR = "coordinator"


class CoordinationPattern(StrEnum):
    CONSENSUS = "consensus"
    AUCTION = "auction"
    VOTING = "voting"
    DELEGATION = "delegation"


class SwarmHealth(StrEnum):
    OPTIMAL = "optimal"
    DEGRADED = "degraded"
    FRAGMENTED = "fragmented"
    FAILED = "failed"


# --- Models ---


class SwarmIntelligenceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    swarm_id: str = ""
    swarm_role: SwarmRole = SwarmRole.WORKER
    coordination_pattern: CoordinationPattern = CoordinationPattern.CONSENSUS
    swarm_health: SwarmHealth = SwarmHealth.OPTIMAL
    task_completion_rate: float = 0.0
    response_time_seconds: float = 0.0
    messages_sent: int = 0
    tasks_assigned: int = 0
    tasks_completed: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SwarmIntelligenceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    swarm_id: str = ""
    coordination_pattern: CoordinationPattern = CoordinationPattern.CONSENSUS
    swarm_health: SwarmHealth = SwarmHealth.OPTIMAL
    coordination_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SwarmIntelligenceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_completion_rate: float = 0.0
    by_swarm_role: dict[str, int] = Field(default_factory=dict)
    by_coordination_pattern: dict[str, int] = Field(default_factory=dict)
    by_swarm_health: dict[str, int] = Field(default_factory=dict)
    unhealthy_swarms: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class SwarmIntelligenceEngine:
    """Analyze multi-agent swarm coordination, identify bottleneck agents,
    and optimize task distribution across agent clusters."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[SwarmIntelligenceRecord] = []
        self._analyses: dict[str, SwarmIntelligenceAnalysis] = {}
        logger.info(
            "swarm_intelligence_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        agent_id: str = "",
        swarm_id: str = "",
        swarm_role: SwarmRole = SwarmRole.WORKER,
        coordination_pattern: CoordinationPattern = CoordinationPattern.CONSENSUS,
        swarm_health: SwarmHealth = SwarmHealth.OPTIMAL,
        task_completion_rate: float = 0.0,
        response_time_seconds: float = 0.0,
        messages_sent: int = 0,
        tasks_assigned: int = 0,
        tasks_completed: int = 0,
        description: str = "",
    ) -> SwarmIntelligenceRecord:
        record = SwarmIntelligenceRecord(
            agent_id=agent_id,
            swarm_id=swarm_id,
            swarm_role=swarm_role,
            coordination_pattern=coordination_pattern,
            swarm_health=swarm_health,
            task_completion_rate=task_completion_rate,
            response_time_seconds=response_time_seconds,
            messages_sent=messages_sent,
            tasks_assigned=tasks_assigned,
            tasks_completed=tasks_completed,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "swarm_intelligence.record_added",
            record_id=record.id,
            agent_id=agent_id,
        )
        return record

    def process(self, key: str) -> SwarmIntelligenceAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        health_weight = {
            SwarmHealth.OPTIMAL: 1.0,
            SwarmHealth.DEGRADED: 0.6,
            SwarmHealth.FRAGMENTED: 0.3,
            SwarmHealth.FAILED: 0.0,
        }
        coordination_score = round(
            rec.task_completion_rate * 0.7 + health_weight.get(rec.swarm_health, 0.0) * 0.3,
            4,
        )
        analysis = SwarmIntelligenceAnalysis(
            swarm_id=rec.swarm_id,
            coordination_pattern=rec.coordination_pattern,
            swarm_health=rec.swarm_health,
            coordination_score=coordination_score,
            description=(
                f"Swarm {rec.swarm_id} -> coordination={coordination_score} "
                f"health={rec.swarm_health.value}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> SwarmIntelligenceReport:
        by_role: dict[str, int] = {}
        by_pattern: dict[str, int] = {}
        by_health: dict[str, int] = {}
        rates: list[float] = []
        for r in self._records:
            by_role[r.swarm_role.value] = by_role.get(r.swarm_role.value, 0) + 1
            by_pattern[r.coordination_pattern.value] = (
                by_pattern.get(r.coordination_pattern.value, 0) + 1
            )
            by_health[r.swarm_health.value] = by_health.get(r.swarm_health.value, 0) + 1
            rates.append(r.task_completion_rate)
        avg_rate = round(sum(rates) / len(rates), 4) if rates else 0.0
        unhealthy = list(
            {
                r.swarm_id
                for r in self._records
                if r.swarm_health in (SwarmHealth.FRAGMENTED, SwarmHealth.FAILED) and r.swarm_id
            }
        )[:10]
        recs: list[str] = []
        if unhealthy:
            recs.append(f"{len(unhealthy)} swarms are fragmented or failed")
        if avg_rate < 0.5:
            recs.append("Average task completion rate is below 50%")
        if not recs:
            recs.append("Swarm intelligence operating within normal parameters")
        return SwarmIntelligenceReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_completion_rate=avg_rate,
            by_swarm_role=by_role,
            by_coordination_pattern=by_pattern,
            by_swarm_health=by_health,
            unhealthy_swarms=unhealthy,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        role_dist: dict[str, int] = {}
        for r in self._records:
            role_dist[r.swarm_role.value] = role_dist.get(r.swarm_role.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "swarm_role_distribution": role_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("swarm_intelligence_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def evaluate_swarm_coordination(self) -> list[dict[str, Any]]:
        """Evaluate coordination effectiveness per swarm."""
        swarm_data: dict[str, list[SwarmIntelligenceRecord]] = {}
        for r in self._records:
            if r.swarm_id:
                swarm_data.setdefault(r.swarm_id, []).append(r)
        results: list[dict[str, Any]] = []
        for swarm_id, recs in swarm_data.items():
            avg_completion = round(sum(r.task_completion_rate for r in recs) / len(recs), 4)
            avg_response = round(sum(r.response_time_seconds for r in recs) / len(recs), 4)
            total_messages = sum(r.messages_sent for r in recs)
            agent_count = len({r.agent_id for r in recs})
            patterns = list({r.coordination_pattern.value for r in recs})
            health_counts: dict[str, int] = {}
            for r in recs:
                health_counts[r.swarm_health.value] = health_counts.get(r.swarm_health.value, 0) + 1
            results.append(
                {
                    "swarm_id": swarm_id,
                    "avg_completion_rate": avg_completion,
                    "avg_response_time": avg_response,
                    "total_messages": total_messages,
                    "agent_count": agent_count,
                    "coordination_patterns": patterns,
                    "health_distribution": health_counts,
                    "rating": (
                        "excellent"
                        if avg_completion >= 0.9
                        else "good"
                        if avg_completion >= 0.7
                        else "needs_improvement"
                    ),
                }
            )
        results.sort(key=lambda x: x["avg_completion_rate"], reverse=True)
        return results

    def identify_bottleneck_agents(self) -> list[dict[str, Any]]:
        """Identify agents that are bottlenecks in swarm coordination."""
        agent_data: dict[str, list[SwarmIntelligenceRecord]] = {}
        for r in self._records:
            if r.agent_id:
                agent_data.setdefault(r.agent_id, []).append(r)
        results: list[dict[str, Any]] = []
        for agent_id, recs in agent_data.items():
            avg_completion = round(sum(r.task_completion_rate for r in recs) / len(recs), 4)
            avg_response = round(sum(r.response_time_seconds for r in recs) / len(recs), 4)
            total_assigned = sum(r.tasks_assigned for r in recs)
            total_completed = sum(r.tasks_completed for r in recs)
            completion_ratio = (
                round(total_completed / total_assigned, 4) if total_assigned > 0 else 0.0
            )
            roles = list({r.swarm_role.value for r in recs})
            is_bottleneck = avg_completion < 0.5 or completion_ratio < 0.5 or avg_response > 60
            if is_bottleneck:
                results.append(
                    {
                        "agent_id": agent_id,
                        "avg_completion_rate": avg_completion,
                        "avg_response_time": avg_response,
                        "tasks_assigned": total_assigned,
                        "tasks_completed": total_completed,
                        "completion_ratio": completion_ratio,
                        "roles": roles,
                        "bottleneck_reason": (
                            "slow_response"
                            if avg_response > 60
                            else "low_completion"
                            if completion_ratio < 0.5
                            else "low_task_rate"
                        ),
                    }
                )
        results.sort(key=lambda x: x["completion_ratio"])
        return results

    def optimize_task_distribution(self) -> list[dict[str, Any]]:
        """Recommend optimal task distribution per coordination pattern."""
        pattern_data: dict[str, list[SwarmIntelligenceRecord]] = {}
        for r in self._records:
            pattern_data.setdefault(r.coordination_pattern.value, []).append(r)
        results: list[dict[str, Any]] = []
        for pattern, recs in pattern_data.items():
            avg_completion = round(sum(r.task_completion_rate for r in recs) / len(recs), 4)
            avg_response = round(sum(r.response_time_seconds for r in recs) / len(recs), 4)
            total_tasks = sum(r.tasks_assigned for r in recs)
            total_completed = sum(r.tasks_completed for r in recs)
            agent_count = len({r.agent_id for r in recs})
            tasks_per_agent = round(total_tasks / agent_count, 4) if agent_count else 0.0
            improvements: list[str] = []
            if avg_completion < 0.7:
                improvements.append("Consider switching to delegation pattern")
            if tasks_per_agent > 10:
                improvements.append("Reduce task load per agent")
            if avg_response > 30:
                improvements.append("Optimize agent response pipeline")
            if not improvements:
                improvements.append("Task distribution is balanced")
            results.append(
                {
                    "coordination_pattern": pattern,
                    "avg_completion_rate": avg_completion,
                    "avg_response_time": avg_response,
                    "total_tasks": total_tasks,
                    "total_completed": total_completed,
                    "agent_count": agent_count,
                    "tasks_per_agent": tasks_per_agent,
                    "improvements": improvements,
                }
            )
        results.sort(key=lambda x: x["avg_completion_rate"], reverse=True)
        return results
