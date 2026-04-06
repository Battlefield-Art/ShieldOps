"""Resource Aware Execution Engine — enforce resource constraints, predict needs, and optimize..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ResourceAwareExecutionEngine = engine(
    "ResourceAwareExecutionEngine",
    description="Enforce resource constraints, predict resource needs, and optimize resource...",
    enums={
        "constraint": EnumDef(
            "ResourceConstraint",
            {
                "MEMORY_CAP": "memory_cap",
                "CPU_CAP": "cpu_cap",
                "TIME_LIMIT": "time_limit",
                "COST_CEILING": "cost_ceiling",
            },
        ),
        "state": EnumDef(
            "ExecutionState",
            {
                "RUNNING": "running",
                "THROTTLED": "throttled",
                "PAUSED": "paused",
                "TERMINATED": "terminated",
            },
        ),
        "violation": EnumDef(
            "ConstraintViolation",
            {
                "SOFT_BREACH": "soft_breach",
                "HARD_BREACH": "hard_breach",
                "PROJECTED_BREACH": "projected_breach",
                "NO_VIOLATION": "no_violation",
            },
        ),
    },
    record_fields=[
        FieldDef("limit_value", float, 0.0),
        FieldDef("current_value", float, 0.0),
        FieldDef("projected_value", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="agent_id",
)

# Backward-compatible re-exports
ResourceConstraint = ResourceAwareExecutionEngine.ResourceConstraint
ExecutionState = ResourceAwareExecutionEngine.ExecutionState
ConstraintViolation = ResourceAwareExecutionEngine.ConstraintViolation
ResourceAwareRecord = ResourceAwareExecutionEngine.Record
ResourceAwareAnalysis = ResourceAwareExecutionEngine.Analysis
ResourceAwareReport = ResourceAwareExecutionEngine.Report
