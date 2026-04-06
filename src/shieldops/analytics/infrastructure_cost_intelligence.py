"""InfrastructureCostIntelligence Infrastructure cost attribution, resource waste detection, o..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

InfrastructureCostIntelligence = engine(
    "InfrastructureCostIntelligence",
    module="operations",  # uses record_item
    description="Infrastructure cost attribution with waste detection and optimization recom...",
    enums={
        "cost_category": EnumDef(
            "CostCategory",
            {
                "COMPUTE": "compute",
                "STORAGE": "storage",
                "NETWORK": "network",
                "DATABASE": "database",
                "OBSERVABILITY": "observability",
                "SECURITY": "security",
            },
        ),
        "waste_type": EnumDef(
            "WasteType",
            {
                "IDLE_RESOURCE": "idle_resource",
                "OVER_PROVISIONED": "over_provisioned",
                "UNATTACHED_VOLUME": "unattached_volume",
                "UNUSED_LICENSE": "unused_license",
                "STALE_SNAPSHOT": "stale_snapshot",
                "ORPHANED_RESOURCE": "orphaned_resource",
            },
        ),
        "optimization_priority": EnumDef(
            "OptimizationPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "INFORMATIONAL": "informational",
            },
        ),
    },
    record_fields=[
        FieldDef("monthly_cost", float, 0.0),
        FieldDef("projected_monthly_cost", float, 0.0),
        FieldDef("potential_savings", float, 0.0),
        FieldDef("utilization_pct", float, 0.0),
        FieldDef("resource_count", int, 0),
        FieldDef("cloud_provider", str, ""),
    ],
)

# Backward-compatible re-exports
CostCategory = InfrastructureCostIntelligence.CostCategory
WasteType = InfrastructureCostIntelligence.WasteType
OptimizationPriority = InfrastructureCostIntelligence.OptimizationPriority
InfrastructureCostRecord = InfrastructureCostIntelligence.Record
InfrastructureCostAnalysis = InfrastructureCostIntelligence.Analysis
InfrastructureCostReport = InfrastructureCostIntelligence.Report
