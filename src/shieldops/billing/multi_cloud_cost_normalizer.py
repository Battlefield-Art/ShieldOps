"""Multi Cloud Cost Normalizer normalize billing taxonomy, reconcile cross-cloud spend, genera..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MultiCloudCostNormalizer = engine(
    "MultiCloudCostNormalizer",
    description="Normalize billing taxonomy, reconcile cross-cloud spend, generate unified v...",
    enums={
        "cloud_provider": EnumDef(
            "CloudProvider",
            {
                "AWS": "aws",
                "GCP": "gcp",
                "AZURE": "azure",
                "ON_PREMISES": "on_premises",
            },
        ),
        "cost_category": EnumDef(
            "CostCategory",
            {
                "COMPUTE": "compute",
                "STORAGE": "storage",
                "NETWORK": "network",
                "MANAGED_SERVICE": "managed_service",
            },
        ),
        "normalization_status": EnumDef(
            "NormalizationStatus",
            {
                "MAPPED": "mapped",
                "APPROXIMATED": "approximated",
                "UNMAPPED": "unmapped",
                "EXCLUDED": "excluded",
            },
        ),
    },
    record_fields=[
        FieldDef("raw_cost", float, 0.0),
        FieldDef("normalized_cost", float, 0.0),
        FieldDef("service_name", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="account_id",
)

# Backward-compatible re-exports
CloudProvider = MultiCloudCostNormalizer.CloudProvider
CostCategory = MultiCloudCostNormalizer.CostCategory
NormalizationStatus = MultiCloudCostNormalizer.NormalizationStatus
CloudCostRecord = MultiCloudCostNormalizer.Record
CloudCostAnalysis = MultiCloudCostNormalizer.Analysis
CloudCostReport = MultiCloudCostNormalizer.Report
