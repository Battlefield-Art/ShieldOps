"""Agent Confidence Calibration Engine — evaluate calibration quality, detect confidence drift..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentConfidenceCalibrationEngine = engine(
    "AgentConfidenceCalibrationEngine",
    description="Calibrate agent confidence scores, detect confidence drift, and optimize ca...",
    enums={
        "calibration_method": EnumDef(
            "CalibrationMethod",
            {
                "PLATT": "platt",
                "ISOTONIC": "isotonic",
                "TEMPERATURE": "temperature",
                "HISTOGRAM": "histogram",
            },
        ),
        "confidence_band": EnumDef(
            "ConfidenceBand",
            {
                "VERY_HIGH": "very_high",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "calibration_quality": EnumDef(
            "CalibrationQuality",
            {
                "WELL_CALIBRATED": "well_calibrated",
                "OVERCONFIDENT": "overconfident",
                "UNDERCONFIDENT": "underconfident",
                "MISCALIBRATED": "miscalibrated",
            },
        ),
    },
    record_fields=[
        FieldDef("predicted_confidence", float, 0.0),
        FieldDef("actual_accuracy", float, 0.0),
        FieldDef("calibration_error", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="agent_id",
)

# Backward-compatible re-exports
CalibrationMethod = AgentConfidenceCalibrationEngine.CalibrationMethod
ConfidenceBand = AgentConfidenceCalibrationEngine.ConfidenceBand
CalibrationQuality = AgentConfidenceCalibrationEngine.CalibrationQuality
ConfidenceCalibrationRecord = AgentConfidenceCalibrationEngine.Record
ConfidenceCalibrationAnalysis = AgentConfidenceCalibrationEngine.Analysis
ConfidenceCalibrationReport = AgentConfidenceCalibrationEngine.Report
