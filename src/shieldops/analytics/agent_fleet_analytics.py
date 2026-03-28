"""AgentFleetAnalytics — fleet utilization."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AgentStatus(StrEnum):
    ACTIVE = "active"
    IDLE = "idle"
    DEGRADED = "degraded"
    OFFLINE = "offline"


class UtilizationRate(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    ZERO = "zero"


class HealthScore(StrEnum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


# --- Models ---


class AgentFleetRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    agent_status: AgentStatus = AgentStatus.ACTIVE
    utilization_rate: UtilizationRate = UtilizationRate.MEDIUM
    health_score: HealthScore = HealthScore.HEALTHY
    score: float = 0.0
    tasks_completed: int = 0
    uptime_pct: float = 100.0
    agent_type: str = ""
    entity: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentFleetAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    agent_status: AgentStatus = AgentStatus.ACTIVE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentFleetReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_agent_status: dict[str, int] = Field(default_factory=dict)
    by_utilization_rate: dict[str, int] = Field(default_factory=dict)
    by_health_score: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentFleetAnalytics:
    """Analyze agent fleet utilization."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AgentFleetRecord] = []
        self._analyses: list[AgentFleetAnalysis] = []
        logger.info(
            "agent_fleet_analytics.init",
            max_records=max_records,
        )

    def add_record(
        self,
        name: str,
        agent_status: AgentStatus = (AgentStatus.ACTIVE),
        utilization_rate: UtilizationRate = (UtilizationRate.MEDIUM),
        health_score: HealthScore = (HealthScore.HEALTHY),
        score: float = 0.0,
        tasks_completed: int = 0,
        uptime_pct: float = 100.0,
        agent_type: str = "",
        entity: str = "",
        service: str = "",
        team: str = "",
    ) -> AgentFleetRecord:
        record = AgentFleetRecord(
            name=name,
            agent_status=agent_status,
            utilization_rate=utilization_rate,
            health_score=health_score,
            score=score,
            tasks_completed=tasks_completed,
            uptime_pct=uptime_pct,
            agent_type=agent_type,
            entity=entity,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_fleet.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> AgentFleetRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        agent_status: AgentStatus | None = None,
        health_score: HealthScore | None = None,
        limit: int = 50,
    ) -> list[AgentFleetRecord]:
        results = list(self._records)
        if agent_status is not None:
            results = [r for r in results if r.agent_status == agent_status]
        if health_score is not None:
            results = [r for r in results if r.health_score == health_score]
        return results[-limit:]

    # -- domain methods ---

    def measure_fleet_utilization(
        self,
    ) -> dict[str, Any]:
        """Measure overall fleet utilization."""
        if not self._records:
            return {
                "total_agents": 0,
                "avg_utilization": 0.0,
            }
        util_dist: dict[str, int] = {}
        for r in self._records:
            k = r.utilization_rate.value
            util_dist[k] = util_dist.get(k, 0) + 1
        active = sum(1 for r in self._records if r.agent_status == AgentStatus.ACTIVE)
        total_tasks = sum(r.tasks_completed for r in self._records)
        return {
            "total_agents": len(self._records),
            "active_agents": active,
            "total_tasks": total_tasks,
            "utilization_distribution": util_dist,
            "active_pct": round(
                active / len(self._records) * 100,
                1,
            ),
        }

    def track_agent_health(
        self,
    ) -> list[dict[str, Any]]:
        """Track health status of each agent."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            results.append(
                {
                    "name": r.name,
                    "agent_type": r.agent_type,
                    "status": (r.agent_status.value),
                    "health": (r.health_score.value),
                    "uptime_pct": r.uptime_pct,
                    "tasks": r.tasks_completed,
                }
            )
        return sorted(
            results,
            key=lambda x: x["uptime_pct"],
        )

    def identify_idle_agents(
        self,
    ) -> list[dict[str, Any]]:
        """Identify idle or underutilized agents."""
        idle: list[dict[str, Any]] = []
        for r in self._records:
            if r.agent_status == AgentStatus.IDLE:
                idle.append(
                    {
                        "name": r.name,
                        "agent_type": (r.agent_type),
                        "utilization": (r.utilization_rate.value),
                        "tasks": (r.tasks_completed),
                        "team": r.team,
                    }
                )
            elif r.utilization_rate == UtilizationRate.ZERO:
                idle.append(
                    {
                        "name": r.name,
                        "agent_type": (r.agent_type),
                        "utilization": "zero",
                        "tasks": (r.tasks_completed),
                        "team": r.team,
                    }
                )
        return idle

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
    ) -> AgentFleetReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.agent_status.value] = by_e1.get(r.agent_status.value, 0) + 1
            by_e2[r.utilization_rate.value] = by_e2.get(r.utilization_rate.value, 0) + 1
            by_e3[r.health_score.value] = by_e3.get(r.health_score.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gaps = [r.name for r in self._records if r.score < self._threshold][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Agent fleet is healthy")
        return AgentFleetReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_agent_status=by_e1,
            by_utilization_rate=by_e2,
            by_health_score=by_e3,
            top_gaps=gaps,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.agent_status.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "status_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_fleet_analytics.cleared")
        return {"status": "cleared"}
