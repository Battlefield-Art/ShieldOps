"""ApiLifecycleEngine API lifecycle management, versioning health, deprecation tracking, and c..."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ApiLifecycleEngine = engine(
    "ApiLifecycleEngine",
    module="operations",  # uses record_item
    description="API lifecycle management with versioning health and deprecation tracking.",
    enums={
        "lifecycle_stage": EnumDef(
            "ApiLifecycleStage",
            {
                "DESIGN": "design",
                "DEVELOPMENT": "development",
                "ACTIVE": "active",
                "DEPRECATED": "deprecated",
                "RETIRED": "retired",
            },
        ),
        "versioning_strategy": EnumDef(
            "ApiVersioningStrategy",
            {
                "URL_PATH": "url_path",
                "HEADER": "header",
                "QUERY_PARAM": "query_param",
                "CONTENT_TYPE": "content_type",
                "CUSTOM": "custom",
            },
        ),
        "health_status": EnumDef(
            "ApiHealthStatus",
            {
                "HEALTHY": "healthy",
                "DEGRADED": "degraded",
                "AT_RISK": "at_risk",
                "CRITICAL": "critical",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
ApiLifecycleStage = ApiLifecycleEngine.ApiLifecycleStage
ApiVersioningStrategy = ApiLifecycleEngine.ApiVersioningStrategy
ApiHealthStatus = ApiLifecycleEngine.ApiHealthStatus
ApiLifecycleRecord = ApiLifecycleEngine.Record
ApiLifecycleAnalysis = ApiLifecycleEngine.Analysis
ApiLifecycleReport = ApiLifecycleEngine.Report
