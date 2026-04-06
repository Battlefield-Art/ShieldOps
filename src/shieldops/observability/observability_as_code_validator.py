"""Observability As Code Validator — observability-as-code configuration validation."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ObservabilityAsCodeValidator = engine(
    "ObservabilityAsCodeValidator",
    description="Observability As Code Validator — observability-as-code configuration valid...",
    enums={
        "config_type": EnumDef(
            "ConfigType",
            {
                "DASHBOARD": "dashboard",
                "ALERT_RULE": "alert_rule",
                "SLO_DEFINITION": "slo_definition",
                "RECORDING_RULE": "recording_rule",
                "PIPELINE": "pipeline",
            },
        ),
        "validation_source": EnumDef(
            "ValidationSource",
            {
                "GIT_REPO": "git_repo",
                "TERRAFORM": "terraform",
                "HELM": "helm",
                "JSONNET": "jsonnet",
                "CUSTOM": "custom",
            },
        ),
        "validation_status": EnumDef(
            "ValidationStatus",
            {
                "VALID": "valid",
                "WARNING": "warning",
                "ERROR": "error",
                "DEPRECATED": "deprecated",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
ConfigType = ObservabilityAsCodeValidator.ConfigType
ValidationSource = ObservabilityAsCodeValidator.ValidationSource
ValidationStatus = ObservabilityAsCodeValidator.ValidationStatus
ValidationRecord = ObservabilityAsCodeValidator.Record
ValidationAnalysis = ObservabilityAsCodeValidator.Analysis
ObservabilityAsCodeReport = ObservabilityAsCodeValidator.Report
