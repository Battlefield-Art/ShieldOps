"""Cross Team Dependency Tracker — map team dependency graph, detect blocking deps, rank depen..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CrossTeamDependencyTracker = engine(
    "CrossTeamDependencyTracker",
    module="operations",  # uses record_item
    description="Map team dependency graph, detect blocking deps, rank dependencies by deliv...",
    enums={
        "dep_type": EnumDef(
            "DependencyType",
            {
                "API": "api",
                "DATA": "data",
                "DEPLOYMENT": "deployment",
                "KNOWLEDGE": "knowledge",
            },
        ),
        "status": EnumDef(
            "BlockingStatus",
            {
                "BLOCKED": "blocked",
                "AT_RISK": "at_risk",
                "MANAGED": "managed",
                "INDEPENDENT": "independent",
            },
        ),
        "scope": EnumDef(
            "ImpactScope",
            {
                "CRITICAL_PATH": "critical_path",
                "PARALLEL": "parallel",
                "OPTIONAL": "optional",
                "INFORMATIONAL": "informational",
            },
        ),
    },
    record_fields=[
        FieldDef("target_team", str, ""),
        FieldDef("wait_time_hours", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="impact_score",
    key_field="source_team",
)

# Backward-compatible re-exports
DependencyType = CrossTeamDependencyTracker.DependencyType
BlockingStatus = CrossTeamDependencyTracker.BlockingStatus
ImpactScope = CrossTeamDependencyTracker.ImpactScope
TeamDependencyRecord = CrossTeamDependencyTracker.Record
TeamDependencyAnalysis = CrossTeamDependencyTracker.Analysis
TeamDependencyReport = CrossTeamDependencyTracker.Report
