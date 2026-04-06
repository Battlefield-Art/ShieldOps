"""Collector Config Drift Engine — detect fleet config drift, classify drift impact, generate..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CollectorConfigDriftEngine = engine(
    "CollectorConfigDriftEngine",
    description="Detect fleet config drift, classify drift impact, generate remediation patc...",
    enums={
        "drift_type": EnumDef(
            "DriftType",
            {
                "RECEIVER_MISMATCH": "receiver_mismatch",
                "PROCESSOR_MISMATCH": "processor_mismatch",
                "EXPORTER_MISMATCH": "exporter_mismatch",
                "RESOURCE_LIMIT_DRIFT": "resource_limit_drift",
            },
        ),
        "drift_severity": EnumDef(
            "DriftSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "config_source": EnumDef(
            "ConfigSource",
            {
                "HELM_VALUES": "helm_values",
                "CONFIGMAP": "configmap",
                "ENV_OVERRIDE": "env_override",
                "DEFAULT": "default",
            },
        ),
    },
    record_fields=[
        FieldDef("drift_field", str, ""),
        FieldDef("expected_value", str, ""),
        FieldDef("actual_value", str, ""),
        FieldDef("drift_age_hours", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="collector_id",
)

# Backward-compatible re-exports
DriftType = CollectorConfigDriftEngine.DriftType
DriftSeverity = CollectorConfigDriftEngine.DriftSeverity
ConfigSource = CollectorConfigDriftEngine.ConfigSource
CollectorConfigDriftRecord = CollectorConfigDriftEngine.Record
CollectorConfigDriftAnalysis = CollectorConfigDriftEngine.Analysis
CollectorConfigDriftReport = CollectorConfigDriftEngine.Report
