"""API Versioning Lifecycle Engine. Track version adoption, detect stale version usage, and fo..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ApiVersioningLifecycleEngine = engine(
    "ApiVersioningLifecycleEngine",
    module="operations",  # uses record_item
    description="Track version adoption, detect stale usage, and forecast deprecation readin...",
    enums={
        "version_status": EnumDef(
            "VersionStatus",
            {
                "CURRENT": "current",
                "DEPRECATED": "deprecated",
                "SUNSET": "sunset",
                "RETIRED": "retired",
            },
        ),
        "adoption_phase": EnumDef(
            "AdoptionPhase",
            {
                "EARLY": "early",
                "GROWING": "growing",
                "MATURE": "mature",
                "DECLINING": "declining",
            },
        ),
        "migration_readiness": EnumDef(
            "MigrationReadiness",
            {
                "READY": "ready",
                "PARTIAL": "partial",
                "BLOCKED": "blocked",
                "UNKNOWN": "unknown",
            },
        ),
    },
    record_fields=[
        FieldDef("version", str, ""),
        FieldDef("consumer_count", int, 0),
        FieldDef("request_share_pct", float, 0.0),
        FieldDef("days_since_release", int, 0),
    ],
    key_field="api_name",
)

# Backward-compatible re-exports
VersionStatus = ApiVersioningLifecycleEngine.VersionStatus
AdoptionPhase = ApiVersioningLifecycleEngine.AdoptionPhase
MigrationReadiness = ApiVersioningLifecycleEngine.MigrationReadiness
ApiVersionRecord = ApiVersioningLifecycleEngine.Record
ApiVersionAnalysis = ApiVersioningLifecycleEngine.Analysis
ApiVersionReport = ApiVersioningLifecycleEngine.Report
