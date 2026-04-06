"""Environment Parity Analyzer compute parity scores, detect environment drift, rank environme..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EnvironmentParityAnalyzer = engine(
    "EnvironmentParityAnalyzer",
    module="operations",  # uses record_item
    description="Compute parity scores, detect environment drift, rank environments by diver...",
    enums={
        "environment_type": EnumDef(
            "EnvironmentType",
            {
                "DEVELOPMENT": "development",
                "STAGING": "staging",
                "PRODUCTION": "production",
                "DISASTER_RECOVERY": "disaster_recovery",
            },
        ),
        "parity_dimension": EnumDef(
            "ParityDimension",
            {
                "CONFIG": "config",
                "VERSION": "version",
                "SCALE": "scale",
                "TOPOLOGY": "topology",
            },
        ),
        "divergence_level": EnumDef(
            "DivergenceLevel",
            {
                "IDENTICAL": "identical",
                "MINOR": "minor",
                "SIGNIFICANT": "significant",
                "CRITICAL": "critical",
            },
        ),
    },
    record_fields=[
        FieldDef("env_name", str, ""),
        FieldDef("reference_env", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="parity_score",
    key_field="env_id",
)

# Backward-compatible re-exports
EnvironmentType = EnvironmentParityAnalyzer.EnvironmentType
ParityDimension = EnvironmentParityAnalyzer.ParityDimension
DivergenceLevel = EnvironmentParityAnalyzer.DivergenceLevel
EnvironmentParityRecord = EnvironmentParityAnalyzer.Record
EnvironmentParityAnalysis = EnvironmentParityAnalyzer.Analysis
EnvironmentParityReport = EnvironmentParityAnalyzer.Report
