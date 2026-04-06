"""IntelligentRetentionManager — intelligent retention manager."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

IntelligentRetentionManager = engine(
    "IntelligentRetentionManager",
    module="operations",  # uses record_item
    description="Intelligent Retention Manager.",
    enums={
        "retention_policy": EnumDef(
            "RetentionPolicy",
            {
                "HOT_30D": "hot_30d",
                "WARM_90D": "warm_90d",
                "COLD_365D": "cold_365d",
                "ARCHIVE_UNLIMITED": "archive_unlimited",
                "CUSTOM": "custom",
            },
        ),
        "data_value": EnumDef(
            "DataValue",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "MINIMAL": "minimal",
            },
        ),
        "retention_action": EnumDef(
            "RetentionAction",
            {
                "RETAIN": "retain",
                "DOWNSAMPLE": "downsample",
                "COMPRESS": "compress",
                "ARCHIVE": "archive",
                "DELETE": "delete",
            },
        ),
    },
)

# Backward-compatible re-exports
RetentionPolicy = IntelligentRetentionManager.RetentionPolicy
DataValue = IntelligentRetentionManager.DataValue
RetentionAction = IntelligentRetentionManager.RetentionAction
IntelligentRetentionManagerRecord = IntelligentRetentionManager.Record
IntelligentRetentionManagerAnalysis = IntelligentRetentionManager.Analysis
IntelligentRetentionManagerReport = IntelligentRetentionManager.Report
