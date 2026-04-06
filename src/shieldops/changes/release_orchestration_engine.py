"""ReleaseOrchestrationEngine Multi-environment release coordination, canary analysis, progres..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ReleaseOrchestrationEngine = engine(
    "ReleaseOrchestrationEngine",
    module="operations",  # uses record_item
    description="Multi-environment release coordination with canary analysis and progressive...",
    enums={
        "stage": EnumDef(
            "ReleaseStage",
            {
                "PLANNED": "planned",
                "CANARY": "canary",
                "PROGRESSIVE": "progressive",
                "FULL_ROLLOUT": "full_rollout",
                "COMPLETED": "completed",
                "ROLLED_BACK": "rolled_back",
            },
        ),
        "rollout_strategy": EnumDef(
            "RolloutStrategy",
            {
                "PERCENTAGE_BASED": "percentage_based",
                "REGION_BASED": "region_based",
                "USER_SEGMENT": "user_segment",
                "RING_BASED": "ring_based",
                "FEATURE_FLAG": "feature_flag",
            },
        ),
        "canary_health": EnumDef(
            "CanaryHealth",
            {
                "HEALTHY": "healthy",
                "DEGRADED": "degraded",
                "UNHEALTHY": "unhealthy",
                "UNKNOWN": "unknown",
                "ABORTED": "aborted",
            },
        ),
    },
    record_fields=[
        FieldDef("version", str, ""),
        FieldDef("rollout_percentage", float, 0.0),
        FieldDef("target_environments", int, 0),
        FieldDef("completed_environments", int, 0),
        FieldDef("error_rate_delta", float, 0.0),
        FieldDef("latency_delta_ms", float, 0.0),
        FieldDef("feature_flags_active", int, 0),
    ],
)

# Backward-compatible re-exports
ReleaseStage = ReleaseOrchestrationEngine.ReleaseStage
RolloutStrategy = ReleaseOrchestrationEngine.RolloutStrategy
CanaryHealth = ReleaseOrchestrationEngine.CanaryHealth
ReleaseOrchestrationRecord = ReleaseOrchestrationEngine.Record
ReleaseOrchestrationAnalysis = ReleaseOrchestrationEngine.Analysis
ReleaseOrchestrationReport = ReleaseOrchestrationEngine.Report
