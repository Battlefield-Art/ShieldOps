"""OtelConfigGeneratorEngine — OTel Collector config generation and validation."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OtelConfigGeneratorEngine = engine(
    "OtelConfigGeneratorEngine",
    description="OTel Collector config generation and validation engine.",
    enums={
        "config_section": EnumDef(
            "ConfigSection",
            {
                "RECEIVERS": "receivers",
                "PROCESSORS": "processors",
                "EXPORTERS": "exporters",
            },
        ),
        "validation_status": EnumDef(
            "ValidationStatus",
            {
                "VALID": "valid",
                "WARNING": "warning",
                "ERROR": "error",
            },
        ),
        "pipeline_signal": EnumDef(
            "PipelineSignal",
            {
                "TRACES": "traces",
                "METRICS": "metrics",
                "LOGS": "logs",
            },
        ),
    },
    record_fields=[
        FieldDef("component_count", int, 0),
        FieldDef("config_hash", str, ""),
    ],
)

# Backward-compatible re-exports
ConfigSection = OtelConfigGeneratorEngine.ConfigSection
ValidationStatus = OtelConfigGeneratorEngine.ValidationStatus
PipelineSignal = OtelConfigGeneratorEngine.PipelineSignal
OtelConfigGeneratorRecord = OtelConfigGeneratorEngine.Record
OtelConfigGeneratorAnalysis = OtelConfigGeneratorEngine.Analysis
OtelConfigGeneratorReport = OtelConfigGeneratorEngine.Report
