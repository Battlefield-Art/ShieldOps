"""HybridCloudTelemetryBridge — cross-cloud bridge."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

HybridCloudTelemetryBridge = engine(
    "HybridCloudTelemetryBridge",
    description="Hybrid Cloud Telemetry Bridge. Bridges telemetry across cloud providers and...",
    enums={
        "provider": EnumDef(
            "CloudProvider",
            {
                "AWS": "aws",
                "GCP": "gcp",
                "AZURE": "azure",
                "ONPREM": "onprem",
            },
        ),
        "status": EnumDef(
            "BridgeStatus",
            {
                "ACTIVE": "active",
                "DEGRADED": "degraded",
                "OFFLINE": "offline",
                "SYNCING": "syncing",
            },
        ),
        "normalization": EnumDef(
            "NormalizationLevel",
            {
                "RAW": "raw",
                "NORMALIZED": "normalized",
                "ENRICHED": "enriched",
            },
        ),
    },
    record_fields=[
        FieldDef("sync_lag_ms", float, 0.0),
        FieldDef("format_match_pct", float, 0.0),
    ],
)

# Backward-compatible re-exports
CloudProvider = HybridCloudTelemetryBridge.CloudProvider
BridgeStatus = HybridCloudTelemetryBridge.BridgeStatus
NormalizationLevel = HybridCloudTelemetryBridge.NormalizationLevel
BridgeRecord = HybridCloudTelemetryBridge.Record
BridgeAnalysis = HybridCloudTelemetryBridge.Analysis
BridgeReport = HybridCloudTelemetryBridge.Report
