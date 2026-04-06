"""Iteration Scheduler Engine Schedule and manage experiment iterations with throughput tracki..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IterationSchedulerEngine = engine(
    "IterationSchedulerEngine",
    module="operations",  # uses record_item
    description="Schedule experiment iterations with throughput tracking and bottleneck dete...",
    enums={
        "strategy": EnumDef(
            "ScheduleStrategy",
            {
                "ROUND_ROBIN": "round_robin",
                "PRIORITY": "priority",
                "DEADLINE": "deadline",
                "ADAPTIVE": "adaptive",
            },
        ),
        "status": EnumDef(
            "IterationStatus",
            {
                "QUEUED": "queued",
                "RUNNING": "running",
                "COMPLETED": "completed",
                "CANCELLED": "cancelled",
            },
        ),
        "constraint": EnumDef(
            "TimeConstraint",
            {
                "MINUTES_5": "minutes_5",
                "MINUTES_15": "minutes_15",
                "HOUR_1": "hour_1",
                "UNLIMITED": "unlimited",
            },
        ),
    },
    record_fields=[
        FieldDef("duration_seconds", float, 0.0),
    ],
)

# Backward-compatible re-exports
ScheduleStrategy = IterationSchedulerEngine.ScheduleStrategy
IterationStatus = IterationSchedulerEngine.IterationStatus
TimeConstraint = IterationSchedulerEngine.TimeConstraint
IterationRecord = IterationSchedulerEngine.Record
IterationAnalysis = IterationSchedulerEngine.Analysis
IterationReport = IterationSchedulerEngine.Report
