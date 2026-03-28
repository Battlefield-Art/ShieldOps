"""Tool functions for Agent Fleet Optimizer."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.agent_fleet_optimizer.models import (
    AgentHealth,
    AgentIssue,
    FleetStatus,
    HealthAnalysis,
    OptimizationAction,
    OptimizationRecommendation,
    ScheduleOptimization,
)

logger = structlog.get_logger()


class AgentFleetOptimizerToolkit:
    """Tools for agent fleet optimization."""

    def __init__(
        self,
        registry_client: Any | None = None,
        metrics_client: Any | None = None,
        scheduler_client: Any | None = None,
    ) -> None:
        self._registry = registry_client
        self._metrics = metrics_client
        self._scheduler = scheduler_client

    async def collect_fleet_status(
        self,
        tenant_id: str,
    ) -> FleetStatus:
        """Collect current fleet status."""
        logger.info(
            "fleet_optimizer.collecting_status",
            tenant_id=tenant_id,
        )

        agents = [
            {
                "name": "investigation",
                "status": "running",
                "health": AgentHealth.HEALTHY,
                "cpu_pct": 35.0,
                "memory_pct": 45.0,
                "last_heartbeat": time.time() - 10,
            },
            {
                "name": "remediation",
                "status": "running",
                "health": AgentHealth.HEALTHY,
                "cpu_pct": 28.0,
                "memory_pct": 38.0,
                "last_heartbeat": time.time() - 5,
            },
            {
                "name": "threat_hunter",
                "status": "idle",
                "health": AgentHealth.IDLE,
                "cpu_pct": 2.0,
                "memory_pct": 15.0,
                "last_heartbeat": time.time() - 300,
            },
            {
                "name": "compliance_auditor",
                "status": "running",
                "health": AgentHealth.DEGRADED,
                "cpu_pct": 92.0,
                "memory_pct": 85.0,
                "last_heartbeat": time.time() - 60,
            },
            {
                "name": "soc_analyst",
                "status": "error",
                "health": AgentHealth.STUCK,
                "cpu_pct": 99.0,
                "memory_pct": 95.0,
                "last_heartbeat": time.time() - 600,
            },
        ]

        running = sum(1 for a in agents if a["status"] == "running")
        idle = sum(1 for a in agents if a["status"] == "idle")
        errored = sum(1 for a in agents if a["status"] == "error")
        avg_cpu = sum(a["cpu_pct"] for a in agents) / len(agents)
        avg_mem = sum(a["memory_pct"] for a in agents) / len(agents)

        return FleetStatus(
            id=f"fleet-{uuid4().hex[:8]}",
            total_agents=len(agents),
            agents_running=running,
            agents_idle=idle,
            agents_errored=errored,
            avg_cpu_pct=round(avg_cpu, 1),
            avg_memory_pct=round(avg_mem, 1),
            agent_statuses=agents,
        )

    async def analyze_health(
        self,
        fleet: FleetStatus,
    ) -> HealthAnalysis:
        """Analyze fleet health patterns."""
        logger.info(
            "fleet_optimizer.analyzing_health",
            total=fleet.total_agents,
        )

        healthy = degraded = stuck = crashed = idle = 0
        for agent in fleet.agent_statuses:
            h = agent.get("health", "")
            if h == AgentHealth.HEALTHY:
                healthy += 1
            elif h == AgentHealth.DEGRADED:
                degraded += 1
            elif h == AgentHealth.STUCK:
                stuck += 1
            elif h == AgentHealth.CRASHED:
                crashed += 1
            elif h == AgentHealth.IDLE:
                idle += 1

        total = fleet.total_agents or 1
        score = round(healthy / total * 100, 1)

        patterns = []
        if stuck > 0:
            patterns.append(f"{stuck} agent(s) stuck — possible deadlock")
        if degraded > 0:
            patterns.append(f"{degraded} agent(s) degraded — resource pressure")
        if idle > total * 0.3:
            patterns.append(f"{idle} agent(s) idle — over-provisioned")

        return HealthAnalysis(
            id=f"ha-{uuid4().hex[:8]}",
            healthy_count=healthy,
            degraded_count=degraded,
            stuck_count=stuck,
            crashed_count=crashed,
            idle_count=idle,
            health_score=score,
            patterns=patterns,
        )

    async def optimize_schedules(
        self,
        fleet: FleetStatus,
        health: HealthAnalysis,
    ) -> list[ScheduleOptimization]:
        """Recommend schedule optimizations."""
        logger.info("fleet_optimizer.optimizing_schedules")

        optimizations: list[ScheduleOptimization] = []
        for agent in fleet.agent_statuses:
            h = agent.get("health", "")
            name = agent.get("name", "unknown")

            if h == AgentHealth.IDLE:
                optimizations.append(
                    ScheduleOptimization(
                        id=f"opt-{uuid4().hex[:8]}",
                        agent_name=name,
                        current_schedule="always_on",
                        recommended_schedule=("on_demand"),
                        reason="Agent idle — switch to on-demand",
                        expected_improvement_pct=40.0,
                    )
                )
            elif h == AgentHealth.DEGRADED:
                cpu = agent.get("cpu_pct", 0)
                if cpu > 80:
                    optimizations.append(
                        ScheduleOptimization(
                            id=f"opt-{uuid4().hex[:8]}",
                            agent_name=name,
                            current_schedule="1x",
                            recommended_schedule="2x",
                            reason=(f"CPU at {cpu}% — scale up"),
                            expected_improvement_pct=25.0,
                        )
                    )

        return optimizations

    async def detect_issues(
        self,
        fleet: FleetStatus,
        health: HealthAnalysis,
    ) -> list[AgentIssue]:
        """Detect fleet issues."""
        logger.info("fleet_optimizer.detecting_issues")

        issues: list[AgentIssue] = []
        now = time.time()

        for agent in fleet.agent_statuses:
            name = agent.get("name", "unknown")
            h = agent.get("health", "")
            hb = agent.get("last_heartbeat", now)

            if h == AgentHealth.STUCK:
                issues.append(
                    AgentIssue(
                        id=f"iss-{uuid4().hex[:8]}",
                        agent_name=name,
                        issue_type="stuck",
                        severity="high",
                        description=(f"{name} stuck, no heartbeat for {int(now - hb)}s"),
                        since=hb,
                        recommended_action=(OptimizationAction.RESTART),
                    )
                )
            elif h == AgentHealth.CRASHED:
                issues.append(
                    AgentIssue(
                        id=f"iss-{uuid4().hex[:8]}",
                        agent_name=name,
                        issue_type="crashed",
                        severity="critical",
                        description=(f"{name} crashed"),
                        since=hb,
                        recommended_action=(OptimizationAction.RESTART),
                    )
                )
            elif h == AgentHealth.DEGRADED:
                cpu = agent.get("cpu_pct", 0)
                if cpu > 90:
                    issues.append(
                        AgentIssue(
                            id=f"iss-{uuid4().hex[:8]}",
                            agent_name=name,
                            issue_type="high_cpu",
                            severity="medium",
                            description=(f"{name} CPU at {cpu}%"),
                            since=hb,
                            recommended_action=(OptimizationAction.SCALE_UP),
                        )
                    )

        return issues

    async def recommend_actions(
        self,
        issues: list[AgentIssue],
        optimizations: list[ScheduleOptimization],
    ) -> list[OptimizationRecommendation]:
        """Generate action recommendations."""
        logger.info(
            "fleet_optimizer.recommending_actions",
            issues=len(issues),
            optimizations=len(optimizations),
        )

        recs: list[OptimizationRecommendation] = []

        for issue in issues:
            recs.append(
                OptimizationRecommendation(
                    id=f"rec-{uuid4().hex[:8]}",
                    action=issue.recommended_action,
                    target_agent=issue.agent_name,
                    reason=issue.description,
                    priority=issue.severity,
                    estimated_impact=("Restore agent to healthy"),
                    auto_executable=(issue.recommended_action == OptimizationAction.RESTART),
                )
            )

        for opt in optimizations:
            recs.append(
                OptimizationRecommendation(
                    id=f"rec-{uuid4().hex[:8]}",
                    action=(OptimizationAction.RESCHEDULE),
                    target_agent=opt.agent_name,
                    reason=opt.reason,
                    priority="low",
                    estimated_impact=(f"{opt.expected_improvement_pct}% improvement"),
                    auto_executable=False,
                )
            )

        return recs
