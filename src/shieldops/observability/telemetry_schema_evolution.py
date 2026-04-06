"""TelemetrySchemaEvolution — telemetry schema evolution."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

TelemetrySchemaEvolution = engine(
    "TelemetrySchemaEvolution",
    description="Telemetry schema evolution engine.",
    enums={
        "schema_change": EnumDef(
            "SchemaChange",
            {
                "FIELD_ADDED": "field_added",
                "FIELD_REMOVED": "field_removed",
                "TYPE_CHANGED": "type_changed",
                "RENAMED": "renamed",
            },
        ),
        "compatibility_level": EnumDef(
            "CompatibilityLevel",
            {
                "BACKWARD": "backward",
                "FORWARD": "forward",
                "FULL": "full",
                "NONE": "none",
            },
        ),
        "migration_status": EnumDef(
            "MigrationStatus",
            {
                "PENDING": "pending",
                "IN_PROGRESS": "in_progress",
                "COMPLETED": "completed",
                "FAILED": "failed",
            },
        ),
    },
)

# Backward-compatible re-exports
SchemaChange = TelemetrySchemaEvolution.SchemaChange
CompatibilityLevel = TelemetrySchemaEvolution.CompatibilityLevel
MigrationStatus = TelemetrySchemaEvolution.MigrationStatus
TelemetrySchemaEvolutionRecord = TelemetrySchemaEvolution.Record
TelemetrySchemaEvolutionAnalysis = TelemetrySchemaEvolution.Analysis
TelemetrySchemaEvolutionReport = TelemetrySchemaEvolution.Report
