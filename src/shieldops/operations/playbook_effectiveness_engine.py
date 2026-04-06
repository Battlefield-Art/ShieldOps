"""Playbook Effectiveness Engine — track SOAR playbook effectiveness."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

PlaybookEffectivenessEngine = engine(
    "PlaybookEffectivenessEngine",
    description="Track SOAR playbook effectiveness.",
    enums={
        "playbook_outcome": EnumDef(
            "PlaybookOutcome",
            {
                "SUCCESS": "success",
                "PARTIAL": "partial",
                "FAILURE": "failure",
                "TIMEOUT": "timeout",
            },
        ),
        "effectiveness_metric": EnumDef(
            "EffectivenessMetric",
            {
                "RESOLUTION_RATE": "resolution_rate",
                "SPEED": "speed",
                "ACCURACY": "accuracy",
                "COVERAGE": "coverage",
            },
        ),
        "improvement_action": EnumDef(
            "ImprovementAction",
            {
                "TUNE": "tune",
                "REPLACE": "replace",
                "MERGE": "merge",
                "DEPRECATE": "deprecate",
            },
        ),
    },
    record_fields=[
        FieldDef("execution_time_s", float, 0.0),
        FieldDef("playbook_id", str, ""),
    ],
)

# Backward-compatible re-exports
PlaybookOutcome = PlaybookEffectivenessEngine.PlaybookOutcome
EffectivenessMetric = PlaybookEffectivenessEngine.EffectivenessMetric
ImprovementAction = PlaybookEffectivenessEngine.ImprovementAction
PlaybookEffectivenessRecord = PlaybookEffectivenessEngine.Record
PlaybookEffectivenessAnalysis = PlaybookEffectivenessEngine.Analysis
PlaybookEffectivenessReport = PlaybookEffectivenessEngine.Report
