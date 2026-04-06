"""Self Contained Agent Profiler Engine — profile agent dependencies, measure self-containment..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SelfContainedAgentProfilerEngine = engine(
    "SelfContainedAgentProfilerEngine",
    description="Profile agent dependencies, measure self-containment score, and recommend d...",
    enums={
        "dependency_type": EnumDef(
            "DependencyType",
            {
                "EXTERNAL_API": "external_api",
                "DATABASE": "database",
                "FILE_SYSTEM": "file_system",
                "NETWORK_SERVICE": "network_service",
            },
        ),
        "profile_metric": EnumDef(
            "ProfileMetric",
            {
                "STARTUP_TIME": "startup_time",
                "MEMORY_FOOTPRINT": "memory_footprint",
                "DEPENDENCY_COUNT": "dependency_count",
                "COLD_START_LATENCY": "cold_start_latency",
            },
        ),
        "optimization_target": EnumDef(
            "OptimizationTarget",
            {
                "MINIMIZE_DEPENDENCIES": "minimize_dependencies",
                "REDUCE_FOOTPRINT": "reduce_footprint",
                "SPEED_STARTUP": "speed_startup",
                "ENABLE_OFFLINE": "enable_offline",
            },
        ),
    },
    record_fields=[
        FieldDef("metric_value", float, 0.0),
        FieldDef("dependency_count", int, 0),
        FieldDef("is_optional", bool, False),
        FieldDef("description", str, ""),
    ],
    key_field="agent_id",
)

# Backward-compatible re-exports
DependencyType = SelfContainedAgentProfilerEngine.DependencyType
ProfileMetric = SelfContainedAgentProfilerEngine.ProfileMetric
OptimizationTarget = SelfContainedAgentProfilerEngine.OptimizationTarget
SelfContainedAgentRecord = SelfContainedAgentProfilerEngine.Record
SelfContainedAgentAnalysis = SelfContainedAgentProfilerEngine.Analysis
SelfContainedAgentReport = SelfContainedAgentProfilerEngine.Report
