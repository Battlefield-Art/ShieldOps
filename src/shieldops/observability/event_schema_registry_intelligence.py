"""Event Schema Registry Intelligence — detect schema conflicts, compute evolution velocity, r..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EventSchemaRegistryIntelligence = engine(
    "EventSchemaRegistryIntelligence",
    description="Detect schema conflicts, compute evolution velocity, rank schemas by compat...",
    enums={
        "schema_format": EnumDef(
            "SchemaFormat",
            {
                "AVRO": "avro",
                "PROTOBUF": "protobuf",
                "JSON_SCHEMA": "json_schema",
                "CUSTOM": "custom",
            },
        ),
        "compatibility_mode": EnumDef(
            "CompatibilityMode",
            {
                "BACKWARD": "backward",
                "FORWARD": "forward",
                "FULL": "full",
                "NONE": "none",
            },
        ),
        "evolution_risk": EnumDef(
            "EvolutionRisk",
            {
                "BREAKING": "breaking",
                "MAJOR": "major",
                "MINOR": "minor",
                "SAFE": "safe",
            },
        ),
    },
    record_fields=[
        FieldDef("version", int, 1),
        FieldDef("field_count", int, 0),
        FieldDef("topic", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="schema_id",
)

# Backward-compatible re-exports
SchemaFormat = EventSchemaRegistryIntelligence.SchemaFormat
CompatibilityMode = EventSchemaRegistryIntelligence.CompatibilityMode
EvolutionRisk = EventSchemaRegistryIntelligence.EvolutionRisk
SchemaRegistryRecord = EventSchemaRegistryIntelligence.Record
SchemaRegistryAnalysis = EventSchemaRegistryIntelligence.Analysis
SchemaRegistryReport = EventSchemaRegistryIntelligence.Report
