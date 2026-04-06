"""Vendor Telemetry Mapper Engine — track and optimize vendor-to-OCSF field mapping accuracy."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

VendorTelemetryMapperEngine = engine(
    "VendorTelemetryMapperEngine",
    description="Track and optimize vendor-to-OCSF field mapping accuracy.",
    enums={
        "mapping_type": EnumDef(
            "MappingType",
            {
                "DIRECT": "direct",
                "TRANSFORM": "transform",
                "COMPUTED": "computed",
                "DEFAULT": "default",
                "UNMAPPED": "unmapped",
            },
        ),
        "field_category": EnumDef(
            "FieldCategory",
            {
                "IDENTITY": "identity",
                "NETWORK": "network",
                "ENDPOINT": "endpoint",
                "CLOUD": "cloud",
                "APPLICATION": "application",
                "METADATA": "metadata",
            },
        ),
        "mapping_accuracy": EnumDef(
            "MappingAccuracy",
            {
                "EXACT": "exact",
                "APPROXIMATE": "approximate",
                "LOSSY": "lossy",
                "FAILED": "failed",
                "NOT_APPLICABLE": "not_applicable",
            },
        ),
    },
    record_fields=[
        FieldDef("ocsf_field", str, ""),
        FieldDef("confidence", float, 0.0),
        FieldDef("transform_rule", str, ""),
    ],
    key_field="vendor_field",
)

# Backward-compatible re-exports
MappingType = VendorTelemetryMapperEngine.MappingType
FieldCategory = VendorTelemetryMapperEngine.FieldCategory
MappingAccuracy = VendorTelemetryMapperEngine.MappingAccuracy
MappingRecord = VendorTelemetryMapperEngine.Record
MappingAnalysis = VendorTelemetryMapperEngine.Analysis
MappingReport = VendorTelemetryMapperEngine.Report
