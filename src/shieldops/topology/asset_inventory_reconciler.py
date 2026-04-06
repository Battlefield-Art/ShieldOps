"""Asset Inventory Reconciler — reconcile asset inventories across multiple sources."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AssetInventoryReconciler = engine(
    "AssetInventoryReconciler",
    description="Reconcile asset inventories across multiple sources to identify discrepancies.",
    enums={
        "reconciliation_status": EnumDef(
            "ReconciliationStatus",
            {
                "MATCHED": "matched",
                "MISMATCHED": "mismatched",
                "MISSING": "missing",
                "STALE": "stale",
                "UNKNOWN": "unknown",
            },
        ),
        "asset_source": EnumDef(
            "AssetSource",
            {
                "CMDB": "cmdb",
                "CLOUD_API": "cloud_api",
                "SCANNER": "scanner",
                "AGENT": "agent",
                "MANUAL": "manual",
            },
        ),
        "discrepancy_type": EnumDef(
            "DiscrepancyType",
            {
                "MISSING_ASSET": "missing_asset",
                "EXTRA_ASSET": "extra_asset",
                "ATTRIBUTE_MISMATCH": "attribute_mismatch",
                "STALE_DATA": "stale_data",
                "CLASSIFICATION_ERROR": "classification_error",
            },
        ),
    },
    score_field="reconciliation_score",
    key_field="asset_name",
)

# Backward-compatible re-exports
ReconciliationStatus = AssetInventoryReconciler.ReconciliationStatus
AssetSource = AssetInventoryReconciler.AssetSource
DiscrepancyType = AssetInventoryReconciler.DiscrepancyType
ReconciliationRecord = AssetInventoryReconciler.Record
ReconciliationAnalysis = AssetInventoryReconciler.Analysis
ReconciliationReport = AssetInventoryReconciler.Report
