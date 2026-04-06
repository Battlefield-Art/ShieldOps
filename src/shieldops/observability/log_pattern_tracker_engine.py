"""Log Pattern Tracker Engine — track log pattern evolution and frequency."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

LogPatternTrackerEngine = engine(
    "LogPatternTrackerEngine",
    description="Track log pattern evolution and frequency across services.",
    enums={
        "pattern_status": EnumDef(
            "PatternStatus",
            {
                "STABLE": "stable",
                "INCREASING": "increasing",
                "DECREASING": "decreasing",
                "NEW": "new",
                "DISAPPEARED": "disappeared",
            },
        ),
        "pattern_category": EnumDef(
            "PatternCategory",
            {
                "NORMAL": "normal",
                "ANOMALOUS": "anomalous",
                "ERROR": "error",
                "SECURITY": "security",
                "PERFORMANCE": "performance",
            },
        ),
        "evolution_type": EnumDef(
            "EvolutionType",
            {
                "FREQUENCY_CHANGE": "frequency_change",
                "FORMAT_CHANGE": "format_change",
                "NEW_PATTERN": "new_pattern",
                "PATTERN_SPLIT": "pattern_split",
                "PATTERN_MERGE": "pattern_merge",
            },
        ),
    },
    record_fields=[
        FieldDef("service_id", str, ""),
        FieldDef("frequency_per_hour", float, 0.0),
        FieldDef("previous_frequency", float, 0.0),
        FieldDef("change_pct", float, 0.0),
        FieldDef("sample_log", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="pattern_id",
)

# Backward-compatible re-exports
PatternStatus = LogPatternTrackerEngine.PatternStatus
PatternCategory = LogPatternTrackerEngine.PatternCategory
EvolutionType = LogPatternTrackerEngine.EvolutionType
LogPatternTrackerRecord = LogPatternTrackerEngine.Record
LogPatternTrackerAnalysis = LogPatternTrackerEngine.Analysis
LogPatternTrackerReport = LogPatternTrackerEngine.Report
