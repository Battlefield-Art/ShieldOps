"""CollectorConfigValidator — collector config validation."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

CollectorConfigValidator = engine(
    "CollectorConfigValidator",
    description="Collector configuration validation engine.",
    enums={
        "config_section": EnumDef(
            "ConfigSection",
            {
                "RECEIVERS": "receivers",
                "PROCESSORS": "processors",
                "EXPORTERS": "exporters",
                "EXTENSIONS": "extensions",
            },
        ),
        "validation_severity": EnumDef(
            "ValidationSeverity",
            {
                "ERROR": "error",
                "WARNING": "warning",
                "INFO": "info",
                "DEPRECATED": "deprecated",
            },
        ),
        "config_format": EnumDef(
            "ConfigFormat",
            {
                "YAML": "yaml",
                "JSON": "json",
                "ENV": "env",
                "CLI": "cli",
            },
        ),
    },
)

# Backward-compatible re-exports
ConfigSection = CollectorConfigValidator.ConfigSection
ValidationSeverity = CollectorConfigValidator.ValidationSeverity
ConfigFormat = CollectorConfigValidator.ConfigFormat
CollectorConfigValidatorRecord = CollectorConfigValidator.Record
CollectorConfigValidatorAnalysis = CollectorConfigValidator.Analysis
CollectorConfigValidatorReport = CollectorConfigValidator.Report
