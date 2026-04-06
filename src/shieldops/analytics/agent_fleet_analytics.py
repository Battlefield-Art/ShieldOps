"""AgentFleetAnalytics — fleet utilization."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentFleetAnalytics = engine(
    "AgentFleetAnalytics",
    description="Analyze agent fleet utilization.",
    enums={
        "agent_status": EnumDef(
            "AgentStatus",
            {
                "ACTIVE": "active",
                "IDLE": "idle",
                "DEGRADED": "degraded",
                "OFFLINE": "offline",
            },
        ),
        "utilization_rate": EnumDef(
            "UtilizationRate",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "ZERO": "zero",
            },
        ),
        "health_score": EnumDef(
            "HealthScore",
            {
                "HEALTHY": "healthy",
                "WARNING": "warning",
                "CRITICAL": "critical",
                "UNKNOWN": "unknown",
            },
        ),
    },
    record_fields=[
        FieldDef("tasks_completed", int, 0),
        FieldDef("uptime_pct", float, 100.0),
        FieldDef("agent_type", str, ""),
        FieldDef("entity", str, ""),
    ],
)

# Backward-compatible re-exports
AgentStatus = AgentFleetAnalytics.AgentStatus
UtilizationRate = AgentFleetAnalytics.UtilizationRate
HealthScore = AgentFleetAnalytics.HealthScore
AgentFleetRecord = AgentFleetAnalytics.Record
AgentFleetAnalysis = AgentFleetAnalytics.Analysis
AgentFleetReport = AgentFleetAnalytics.Report
