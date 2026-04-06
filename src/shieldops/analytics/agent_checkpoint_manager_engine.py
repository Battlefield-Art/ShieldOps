"""Agent Checkpoint Manager Engine — evaluate checkpoint quality, select rollback targets, and..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentCheckpointManagerEngine = engine(
    "AgentCheckpointManagerEngine",
    description="Evaluate checkpoint quality, select rollback targets, and prune redundant c...",
    enums={
        "trigger": EnumDef(
            "CheckpointTrigger",
            {
                "IMPROVEMENT_FOUND": "improvement_found",
                "PERIODIC": "periodic",
                "PHASE_TRANSITION": "phase_transition",
                "MANUAL": "manual",
            },
        ),
        "quality": EnumDef(
            "CheckpointQuality",
            {
                "BEST_SO_FAR": "best_so_far",
                "ABOVE_BASELINE": "above_baseline",
                "BELOW_BASELINE": "below_baseline",
                "CORRUPTED": "corrupted",
            },
        ),
        "rollback_reason": EnumDef(
            "RollbackReason",
            {
                "REGRESSION_DETECTED": "regression_detected",
                "INSTABILITY": "instability",
                "RESOURCE_ISSUE": "resource_issue",
                "EXPERIMENT_FAILED": "experiment_failed",
            },
        ),
    },
    record_fields=[
        FieldDef("checkpoint_id", str, ""),
        FieldDef("baseline_score", float, 0.0),
        FieldDef("size_mb", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="metric_score",
    key_field="agent_id",
)

# Backward-compatible re-exports
CheckpointTrigger = AgentCheckpointManagerEngine.CheckpointTrigger
CheckpointQuality = AgentCheckpointManagerEngine.CheckpointQuality
RollbackReason = AgentCheckpointManagerEngine.RollbackReason
AgentCheckpointRecord = AgentCheckpointManagerEngine.Record
AgentCheckpointAnalysis = AgentCheckpointManagerEngine.Analysis
AgentCheckpointReport = AgentCheckpointManagerEngine.Report
