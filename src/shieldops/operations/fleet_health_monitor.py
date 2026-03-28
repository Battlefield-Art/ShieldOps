"""Fleet Health Monitor — check agent health and resources."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class HealthCheck(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ResourceUsage(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class AlertThreshold(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# --- Models ---


class HealthRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = ""
    health: HealthCheck = HealthCheck.HEALTHY
    resource_usage: ResourceUsage = ResourceUsage.LOW
    alert_level: AlertThreshold = AlertThreshold.INFO
    score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class HealthAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = ""
    health: HealthCheck = HealthCheck.HEALTHY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class HealthReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_score: float = 0.0
    by_health: dict[str, int] = Field(default_factory=dict)
    by_usage: dict[str, int] = Field(default_factory=dict)
    by_alert: dict[str, int] = Field(default_factory=dict)
    unhealthy_agents: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class FleetHealthMonitor:
    """Monitor agent fleet health and resources."""

    def __init__(
        self,
        max_records: int = 200000,
        health_threshold: float = 70.0,
    ) -> None:
        self._max = max_records
        self._health_threshold = health_threshold
        self._records: list[HealthRecord] = []
        self._analyses: list[HealthAnalysis] = []
        logger.info(
            "fleet_health_monitor.initialized",
            max_records=max_records,
        )

    def record_item(
        self,
        agent_name: str = "",
        health: HealthCheck = HealthCheck.HEALTHY,
        resource_usage: ResourceUsage = (ResourceUsage.LOW),
        alert_level: AlertThreshold = (AlertThreshold.INFO),
        score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> HealthRecord:
        rec = HealthRecord(
            agent_name=agent_name,
            health=health,
            resource_usage=resource_usage,
            alert_level=alert_level,
            score=score,
            service=service,
            team=team,
        )
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "fleet_health_monitor.item_recorded",
            record_id=rec.id,
        )
        return rec

    def process(self, key: str) -> HealthAnalysis:
        matches = [r for r in self._records if r.agent_name == key]
        total = sum(r.score for r in matches)
        avg = total / len(matches) if matches else 0.0
        analysis = HealthAnalysis(
            agent_name=key,
            analysis_score=round(avg, 2),
            threshold=self._health_threshold,
            breached=avg < self._health_threshold,
            description=(f"Checked {len(matches)} records"),
        )
        self._analyses.append(analysis)
        return analysis

    # -- domain methods ---

    def check_agent_health(
        self,
        agent: str,
    ) -> dict[str, Any]:
        """Latest health status for an agent."""
        matches = [r for r in self._records if r.agent_name == agent]
        if not matches:
            return {
                "agent": agent,
                "health": "unknown",
            }
        latest = matches[-1]
        return {
            "agent": agent,
            "health": latest.health.value,
            "resource_usage": (latest.resource_usage.value),
            "score": latest.score,
        }

    def measure_resource_usage(
        self,
    ) -> dict[str, Any]:
        """Aggregate resource usage across fleet."""
        usage: dict[str, int] = {}
        for r in self._records:
            k = r.resource_usage.value
            usage[k] = usage.get(k, 0) + 1
        return {
            "distribution": usage,
            "total": len(self._records),
        }

    def trigger_alert(
        self,
    ) -> list[dict[str, Any]]:
        """Find agents above alert threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.health in (
                HealthCheck.UNHEALTHY,
                HealthCheck.DEGRADED,
            ):
                results.append(
                    {
                        "id": r.id,
                        "agent": r.agent_name,
                        "health": r.health.value,
                        "alert": r.alert_level.value,
                    }
                )
        return results

    # -- report / stats ---

    def generate_report(self) -> HealthReport:
        by_health: dict[str, int] = {}
        by_usage: dict[str, int] = {}
        by_alert: dict[str, int] = {}
        for r in self._records:
            h = r.health.value
            by_health[h] = by_health.get(h, 0) + 1
            u = r.resource_usage.value
            by_usage[u] = by_usage.get(u, 0) + 1
            a = r.alert_level.value
            by_alert[a] = by_alert.get(a, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        bad = [r.agent_name for r in self._records if r.health == HealthCheck.UNHEALTHY][:5]
        recs: list[str] = []
        if bad:
            recs.append(f"{len(bad)} agent(s) unhealthy")
        if not recs:
            recs.append("Fleet health is good")
        return HealthReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_score=avg,
            by_health=by_health,
            by_usage=by_usage,
            by_alert=by_alert,
            unhealthy_agents=bad,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.health.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "health_threshold": self._health_threshold,
            "health_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("fleet_health_monitor.cleared")
        return {"status": "cleared"}
