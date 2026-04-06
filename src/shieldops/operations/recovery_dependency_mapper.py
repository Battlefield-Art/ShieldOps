"""Recovery Dependency Mapper — compute recovery critical path, detect circular dependencies,..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RecoveryDependencyMapper = engine(
    "RecoveryDependencyMapper",
    module="operations",  # uses record_item
    description="Compute recovery critical path, detect circular dependencies, rank services...",
    enums={
        "dependency_type": EnumDef(
            "DependencyType",
            {
                "HARD": "hard",
                "SOFT": "soft",
                "OPTIONAL": "optional",
                "CONDITIONAL": "conditional",
            },
        ),
        "recovery_order": EnumDef(
            "RecoveryOrder",
            {
                "PARALLEL": "parallel",
                "SEQUENTIAL": "sequential",
                "STAGED": "staged",
                "PRIORITY": "priority",
            },
        ),
        "dependency_risk": EnumDef(
            "DependencyRisk",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("source_service", str, ""),
        FieldDef("target_service", str, ""),
        FieldDef("recovery_time_seconds", float, 0.0),
    ],
)

# Backward-compatible re-exports
DependencyType = RecoveryDependencyMapper.DependencyType
RecoveryOrder = RecoveryDependencyMapper.RecoveryOrder
DependencyRisk = RecoveryDependencyMapper.DependencyRisk
RecoveryDependencyRecord = RecoveryDependencyMapper.Record
RecoveryDependencyAnalysis = RecoveryDependencyMapper.Analysis
RecoveryDependencyReport = RecoveryDependencyMapper.Report
