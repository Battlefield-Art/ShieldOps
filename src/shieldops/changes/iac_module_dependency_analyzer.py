"""IaC Module Dependency Analyzer map module dependency graphs, detect circular dependencies,..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IacModuleDependencyAnalyzer = engine(
    "IacModuleDependencyAnalyzer",
    module="operations",  # uses record_item
    description="Map module dependency graphs, detect circular dependencies, rank modules by...",
    enums={
        "module_source": EnumDef(
            "ModuleSource",
            {
                "REGISTRY": "registry",
                "GIT": "git",
                "LOCAL": "local",
                "S3": "s3",
            },
        ),
        "dependency_depth": EnumDef(
            "DependencyDepth",
            {
                "DIRECT": "direct",
                "TRANSITIVE": "transitive",
                "DEEP": "deep",
                "CIRCULAR": "circular",
            },
        ),
        "update_risk": EnumDef(
            "UpdateRisk",
            {
                "BREAKING": "breaking",
                "MAJOR": "major",
                "MINOR": "minor",
                "PATCH": "patch",
            },
        ),
    },
    record_fields=[
        FieldDef("module_name", str, ""),
        FieldDef("dependent_count", int, 0),
        FieldDef("dependency_count", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="module_id",
)

# Backward-compatible re-exports
ModuleSource = IacModuleDependencyAnalyzer.ModuleSource
DependencyDepth = IacModuleDependencyAnalyzer.DependencyDepth
UpdateRisk = IacModuleDependencyAnalyzer.UpdateRisk
ModuleDependencyRecord = IacModuleDependencyAnalyzer.Record
ModuleDependencyAnalysis = IacModuleDependencyAnalyzer.Analysis
ModuleDependencyReport = IacModuleDependencyAnalyzer.Report
