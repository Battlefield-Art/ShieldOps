"""Lightweight Eval Harness Engine — select eval mode, estimate accuracy, and calibrate proxy..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

LightweightEvalHarnessEngine = engine(
    "LightweightEvalHarnessEngine",
    description="Select eval mode, estimate eval accuracy, and calibrate proxy metrics.",
    enums={
        "eval_mode": EnumDef(
            "EvalMode",
            {
                "FULL_SUITE": "full_suite",
                "SAMPLED_SUITE": "sampled_suite",
                "PROXY_METRIC": "proxy_metric",
                "FAST_CHECK": "fast_check",
            },
        ),
        "reliability": EnumDef(
            "EvalReliability",
            {
                "DEFINITIVE": "definitive",
                "HIGH_CONFIDENCE": "high_confidence",
                "INDICATIVE": "indicative",
                "NOISY": "noisy",
            },
        ),
        "eval_cost": EnumDef(
            "EvalCost",
            {
                "EXPENSIVE": "expensive",
                "MODERATE": "moderate",
                "CHEAP": "cheap",
                "FREE": "free",
            },
        ),
    },
    record_fields=[
        FieldDef("proxy_score", float, 0.0),
        FieldDef("duration_seconds", float, 0.0),
        FieldDef("sample_fraction", float, 1.0),
        FieldDef("description", str, ""),
    ],
    score_field="eval_score",
    key_field="experiment_id",
)

# Backward-compatible re-exports
EvalMode = LightweightEvalHarnessEngine.EvalMode
EvalReliability = LightweightEvalHarnessEngine.EvalReliability
EvalCost = LightweightEvalHarnessEngine.EvalCost
LightweightEvalRecord = LightweightEvalHarnessEngine.Record
LightweightEvalAnalysis = LightweightEvalHarnessEngine.Analysis
LightweightEvalReport = LightweightEvalHarnessEngine.Report
