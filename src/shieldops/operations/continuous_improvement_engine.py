"""ContinuousImprovementEngine — continuous improvement engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ContinuousImprovementEngine = engine(
    "ContinuousImprovementEngine",
    module="operations",  # uses record_item
    description="Continuous Improvement Engine.",
    enums={
        "improvement_type": EnumDef(
            "ImprovementType",
            {
                "PROCESS": "process",
                "TOOLING": "tooling",
                "AUTOMATION": "automation",
                "TRAINING": "training",
                "ARCHITECTURE": "architecture",
            },
        ),
        "improvement_status": EnumDef(
            "ImprovementStatus",
            {
                "PROPOSED": "proposed",
                "APPROVED": "approved",
                "IN_PROGRESS": "in_progress",
                "COMPLETED": "completed",
                "DEFERRED": "deferred",
            },
        ),
        "impact_level": EnumDef(
            "ImpactLevel",
            {
                "TRANSFORMATIONAL": "transformational",
                "SIGNIFICANT": "significant",
                "MODERATE": "moderate",
                "INCREMENTAL": "incremental",
                "MINIMAL": "minimal",
            },
        ),
    },
)

# Backward-compatible re-exports
ImprovementType = ContinuousImprovementEngine.ImprovementType
ImprovementStatus = ContinuousImprovementEngine.ImprovementStatus
ImpactLevel = ContinuousImprovementEngine.ImpactLevel
ContinuousImprovementEngineRecord = ContinuousImprovementEngine.Record
ContinuousImprovementEngineAnalysis = ContinuousImprovementEngine.Analysis
ContinuousImprovementEngineReport = ContinuousImprovementEngine.Report
