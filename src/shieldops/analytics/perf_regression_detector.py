"""Performance Regression Detector compute regression magnitude, detect latent regressions, ra..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

PerfRegressionDetector = engine(
    "PerfRegressionDetector",
    description="Compute regression magnitude, detect latent regressions, rank deployments b...",
    enums={
        "regression_severity": EnumDef(
            "RegressionSeverity",
            {
                "CRITICAL": "critical",
                "MAJOR": "major",
                "MINOR": "minor",
                "NEGLIGIBLE": "negligible",
            },
        ),
        "detection_method": EnumDef(
            "DetectionMethod",
            {
                "BASELINE_COMPARISON": "baseline_comparison",
                "STATISTICAL": "statistical",
                "ML_BASED": "ml_based",
                "THRESHOLD": "threshold",
            },
        ),
        "regression_type": EnumDef(
            "RegressionType",
            {
                "LATENCY": "latency",
                "THROUGHPUT": "throughput",
                "ERROR_RATE": "error_rate",
                "RESOURCE": "resource",
            },
        ),
    },
    record_fields=[
        FieldDef("magnitude", float, 0.0),
        FieldDef("baseline_value", float, 0.0),
        FieldDef("current_value", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="deployment_id",
)

# Backward-compatible re-exports
RegressionSeverity = PerfRegressionDetector.RegressionSeverity
DetectionMethod = PerfRegressionDetector.DetectionMethod
RegressionType = PerfRegressionDetector.RegressionType
PerfRegressionRecord = PerfRegressionDetector.Record
PerfRegressionAnalysis = PerfRegressionDetector.Analysis
PerfRegressionReport = PerfRegressionDetector.Report
