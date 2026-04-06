"""AutoInstrumentationManager — auto-instrumentation orchestration."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutoInstrumentationManager = engine(
    "AutoInstrumentationManager",
    description="Auto-instrumentation orchestration engine.",
    enums={
        "instrumentation_target": EnumDef(
            "InstrumentationTarget",
            {
                "PYTHON": "python",
                "JAVA": "java",
                "NODEJS": "nodejs",
                "DOTNET": "dotnet",
            },
        ),
        "instrumentation_method": EnumDef(
            "InstrumentationMethod",
            {
                "AUTO": "auto",
                "MANUAL": "manual",
                "HYBRID": "hybrid",
                "SDK": "sdk",
            },
        ),
        "coverage_level": EnumDef(
            "CoverageLevel",
            {
                "FULL": "full",
                "PARTIAL": "partial",
                "MINIMAL": "minimal",
                "NONE": "none",
            },
        ),
    },
)

# Backward-compatible re-exports
InstrumentationTarget = AutoInstrumentationManager.InstrumentationTarget
InstrumentationMethod = AutoInstrumentationManager.InstrumentationMethod
CoverageLevel = AutoInstrumentationManager.CoverageLevel
AutoInstrumentationManagerRecord = AutoInstrumentationManager.Record
AutoInstrumentationManagerAnalysis = AutoInstrumentationManager.Analysis
AutoInstrumentationManagerReport = AutoInstrumentationManager.Report
