"""Resource Rightsizing Intelligence profile workload utilization, recommend instance family,..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ResourceRightsizingIntelligence = engine(
    "ResourceRightsizingIntelligence",
    module="operations",  # uses record_item
    description="Profile workload utilization, recommend instance family, validate safety.",
    enums={
        "workload_profile": EnumDef(
            "WorkloadProfile",
            {
                "STEADY": "steady",
                "BURSTY": "bursty",
                "BATCH": "batch",
                "IDLE_HEAVY": "idle_heavy",
            },
        ),
        "sizing_action": EnumDef(
            "SizingAction",
            {
                "DOWNSIZE": "downsize",
                "UPSIZE": "upsize",
                "CHANGE_FAMILY": "change_family",
                "MAINTAIN": "maintain",
            },
        ),
        "safety_level": EnumDef(
            "SafetyLevel",
            {
                "SAFE": "safe",
                "CAUTION": "caution",
                "RISKY": "risky",
                "BLOCKED": "blocked",
            },
        ),
    },
    record_fields=[
        FieldDef("cpu_utilization", float, 0.0),
        FieldDef("memory_utilization", float, 0.0),
        FieldDef("monthly_cost", float, 0.0),
        FieldDef("instance_type", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="resource_id",
)

# Backward-compatible re-exports
WorkloadProfile = ResourceRightsizingIntelligence.WorkloadProfile
SizingAction = ResourceRightsizingIntelligence.SizingAction
SafetyLevel = ResourceRightsizingIntelligence.SafetyLevel
RightsizingRecord = ResourceRightsizingIntelligence.Record
RightsizingAnalysis = ResourceRightsizingIntelligence.Analysis
RightsizingReport = ResourceRightsizingIntelligence.Report
