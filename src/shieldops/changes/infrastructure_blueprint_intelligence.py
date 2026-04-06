"""Infrastructure Blueprint Intelligence analyze blueprint adoption, detect blueprint drift, r..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

InfrastructureBlueprintIntelligence = engine(
    "InfrastructureBlueprintIntelligence",
    module="operations",  # uses record_item
    description="Analyze blueprint adoption, detect blueprint drift, rank blueprints by reus...",
    enums={
        "blueprint_status": EnumDef(
            "BlueprintStatus",
            {
                "CURRENT": "current",
                "OUTDATED": "outdated",
                "DEPRECATED": "deprecated",
                "ARCHIVED": "archived",
            },
        ),
        "adoption_level": EnumDef(
            "AdoptionLevel",
            {
                "WIDESPREAD": "widespread",
                "MODERATE": "moderate",
                "LIMITED": "limited",
                "NONE": "none",
            },
        ),
        "blueprint_type": EnumDef(
            "BlueprintType",
            {
                "NETWORK": "network",
                "COMPUTE": "compute",
                "DATABASE": "database",
                "SECURITY": "security",
            },
        ),
    },
    record_fields=[
        FieldDef("blueprint_name", str, ""),
        FieldDef("adoption_count", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="drift_score",
    key_field="blueprint_id",
)

# Backward-compatible re-exports
BlueprintStatus = InfrastructureBlueprintIntelligence.BlueprintStatus
AdoptionLevel = InfrastructureBlueprintIntelligence.AdoptionLevel
BlueprintType = InfrastructureBlueprintIntelligence.BlueprintType
BlueprintIntelligenceRecord = InfrastructureBlueprintIntelligence.Record
BlueprintIntelligenceAnalysis = InfrastructureBlueprintIntelligence.Analysis
BlueprintIntelligenceReport = InfrastructureBlueprintIntelligence.Report
