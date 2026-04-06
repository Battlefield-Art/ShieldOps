"""EnvironmentParityEngine Cross-environment comparison, parity scoring, deviation alerting, s..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EnvironmentParityEngine = engine(
    "EnvironmentParityEngine",
    module="operations",  # uses record_item
    description="Cross-environment comparison with parity scoring and deviation alerting.",
    enums={
        "source_env": EnumDef(
            "EnvironmentType",
            {
                "DEVELOPMENT": "development",
                "STAGING": "staging",
                "PRODUCTION": "production",
                "DR_SITE": "dr_site",
                "CANARY": "canary",
            },
        ),
        "deviation_type": EnumDef(
            "DeviationType",
            {
                "VERSION_MISMATCH": "version_mismatch",
                "CONFIG_DRIFT": "config_drift",
                "RESOURCE_SIZING": "resource_sizing",
                "FEATURE_FLAG": "feature_flag",
                "DEPENDENCY_GAP": "dependency_gap",
                "SECURITY_POLICY": "security_policy",
            },
        ),
        "parity_level": EnumDef(
            "ParityLevel",
            {
                "IDENTICAL": "identical",
                "MINOR_DEVIATION": "minor_deviation",
                "SIGNIFICANT_DEVIATION": "significant_deviation",
                "CRITICAL_DEVIATION": "critical_deviation",
                "INCOMPATIBLE": "incompatible",
            },
        ),
    },
    record_fields=[
        FieldDef("deviations_found", int, 0),
        FieldDef("source_version", str, ""),
        FieldDef("target_version", str, ""),
    ],
    score_field="parity_score",
)

# Backward-compatible re-exports
EnvironmentType = EnvironmentParityEngine.EnvironmentType
DeviationType = EnvironmentParityEngine.DeviationType
ParityLevel = EnvironmentParityEngine.ParityLevel
EnvironmentParityRecord = EnvironmentParityEngine.Record
EnvironmentParityAnalysis = EnvironmentParityEngine.Analysis
EnvironmentParityReport = EnvironmentParityEngine.Report
