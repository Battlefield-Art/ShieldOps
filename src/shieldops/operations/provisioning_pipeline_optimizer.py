"""Provisioning Pipeline Optimizer compute pipeline efficiency, detect bottlenecks, rank stage..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ProvisioningPipelineOptimizer = engine(
    "ProvisioningPipelineOptimizer",
    module="operations",  # uses record_item
    description="Compute pipeline efficiency, detect bottlenecks, rank stages by optimization.",
    enums={
        "pipeline_stage": EnumDef(
            "PipelineStage",
            {
                "PLAN": "plan",
                "VALIDATE": "validate",
                "APPLY": "apply",
                "VERIFY": "verify",
            },
        ),
        "stage_status": EnumDef(
            "StageStatus",
            {
                "PASSED": "passed",
                "FAILED": "failed",
                "SLOW": "slow",
                "SKIPPED": "skipped",
            },
        ),
        "optimization_type": EnumDef(
            "OptimizationType",
            {
                "PARALLELIZATION": "parallelization",
                "CACHING": "caching",
                "BATCHING": "batching",
                "ELIMINATION": "elimination",
            },
        ),
    },
    record_fields=[
        FieldDef("stage_name", str, ""),
        FieldDef("duration_seconds", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="efficiency_score",
    key_field="pipeline_id",
)

# Backward-compatible re-exports
PipelineStage = ProvisioningPipelineOptimizer.PipelineStage
StageStatus = ProvisioningPipelineOptimizer.StageStatus
OptimizationType = ProvisioningPipelineOptimizer.OptimizationType
PipelineOptimizationRecord = ProvisioningPipelineOptimizer.Record
PipelineOptimizationAnalysis = ProvisioningPipelineOptimizer.Analysis
PipelineOptimizationReport = ProvisioningPipelineOptimizer.Report
