"""Self-Tuning Alert Engine Continuously optimizes alert rules by tracking signal quality, rec..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SelfTuningAlertEngine = engine(
    "SelfTuningAlertEngine",
    description="Self-Tuning Alert Engine Optimizes alert rules by tracking signal quality,...",
    enums={
        "signal_quality": EnumDef(
            "AlertSignalQuality",
            {
                "HIGH_SIGNAL": "high_signal",
                "MODERATE_SIGNAL": "moderate_signal",
                "LOW_SIGNAL": "low_signal",
                "NOISE": "noise",
                "UNKNOWN": "unknown",
            },
        ),
        "tuning_action": EnumDef(
            "TuningAction",
            {
                "TIGHTEN_THRESHOLD": "tighten_threshold",
                "LOOSEN_THRESHOLD": "loosen_threshold",
                "CHANGE_ROUTING": "change_routing",
                "ADD_CONTEXT": "add_context",
                "SUPPRESS": "suppress",
            },
        ),
        "tuning_outcome": EnumDef(
            "TuningOutcome",
            {
                "IMPROVED": "improved",
                "NO_CHANGE": "no_change",
                "DEGRADED": "degraded",
                "PENDING": "pending",
            },
        ),
    },
    record_fields=[
        FieldDef("action_taken_ratio", float, 0.0),
        FieldDef("response_time_sec", float, 0.0),
        FieldDef("acknowledged", bool, False),
        FieldDef("false_positive_rate", float, 0.0),
    ],
    key_field="alert_rule_id",
)

# Backward-compatible re-exports
AlertSignalQuality = SelfTuningAlertEngine.AlertSignalQuality
TuningAction = SelfTuningAlertEngine.TuningAction
TuningOutcome = SelfTuningAlertEngine.TuningOutcome
AlertTuningRecord = SelfTuningAlertEngine.Record
AlertTuningAnalysis = SelfTuningAlertEngine.Analysis
AlertTuningReport = SelfTuningAlertEngine.Report
