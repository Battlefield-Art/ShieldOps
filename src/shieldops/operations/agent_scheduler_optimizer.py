"""Agent Scheduler Optimizer — detect conflicts and balance load."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AgentSchedulerOptimizer = engine(
    "AgentSchedulerOptimizer",
    module="operations",  # uses record_item
    description="Optimize agent scheduling and load balance.",
    enums={
        "conflict": EnumDef(
            "ScheduleConflict",
            {
                "NONE": "none",
                "OVERLAP": "overlap",
                "RESOURCE": "resource",
                "DEPENDENCY": "dependency",
            },
        ),
        "load": EnumDef(
            "LoadBalance",
            {
                "BALANCED": "balanced",
                "SKEWED": "skewed",
                "OVERLOADED": "overloaded",
                "IDLE": "idle",
            },
        ),
        "priority": EnumDef(
            "PriorityQueue",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    key_field="agent_name",
)

# Backward-compatible re-exports
ScheduleConflict = AgentSchedulerOptimizer.ScheduleConflict
LoadBalance = AgentSchedulerOptimizer.LoadBalance
PriorityQueue = AgentSchedulerOptimizer.PriorityQueue
SchedulerRecord = AgentSchedulerOptimizer.Record
SchedulerAnalysis = AgentSchedulerOptimizer.Analysis
SchedulerReport = AgentSchedulerOptimizer.Report
