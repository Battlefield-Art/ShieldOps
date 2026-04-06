"""Resource Waste Classifier Engine — classify and track resource waste across clouds."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ResourceWasteClassifierEngine = engine(
    "ResourceWasteClassifierEngine",
    description="Resource Waste Classifier Engine — classify and track resource waste.",
    enums={
        "waste_category": EnumDef(
            "WasteCategory",
            {
                "IDLE_COMPUTE": "idle_compute",
                "OVERSIZED_INSTANCE": "oversized_instance",
                "UNUSED_STORAGE": "unused_storage",
                "ORPHANED_RESOURCE": "orphaned_resource",
                "UNATTACHED_VOLUME": "unattached_volume",
            },
        ),
        "waste_severity": EnumDef(
            "WasteSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "NEGLIGIBLE": "negligible",
            },
        ),
        "reclamation_status": EnumDef(
            "ReclamationStatus",
            {
                "IDENTIFIED": "identified",
                "APPROVED": "approved",
                "RECLAIMED": "reclaimed",
                "DEFERRED": "deferred",
                "EXEMPTED": "exempted",
            },
        ),
    },
    record_fields=[
        FieldDef("monthly_waste_usd", float, 0.0),
        FieldDef("utilization_pct", float, 0.0),
        FieldDef("days_idle", int, 0),
    ],
    key_field="resource_id",
)

# Backward-compatible re-exports
WasteCategory = ResourceWasteClassifierEngine.WasteCategory
WasteSeverity = ResourceWasteClassifierEngine.WasteSeverity
ReclamationStatus = ResourceWasteClassifierEngine.ReclamationStatus
ResourceWasteRecord = ResourceWasteClassifierEngine.Record
ResourceWasteAnalysis = ResourceWasteClassifierEngine.Analysis
ResourceWasteReport = ResourceWasteClassifierEngine.Report
