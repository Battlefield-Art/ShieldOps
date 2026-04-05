"""API Exposure Analyzer — analyze API endpoints for security exposures."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

APIExposureAnalyzer = engine(
    "APIExposureAnalyzer",
    description="Analyze API endpoints for security exposures, shadow APIs, and misconfigura...",
    enums={
        "api_type": EnumDef(
            "APIType",
            {
                "REST": "rest",
                "GRAPHQL": "graphql",
                "GRPC": "grpc",
                "WEBSOCKET": "websocket",
                "SOAP": "soap",
            },
        ),
        "exposure_level": EnumDef(
            "ExposureLevel",
            {
                "PUBLIC": "public",
                "PARTNER": "partner",
                "INTERNAL": "internal",
                "DEPRECATED": "deprecated",
                "SHADOW": "shadow",
            },
        ),
        "api_risk": EnumDef(
            "APIRisk",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "MINIMAL": "minimal",
            },
        ),
    },
    score_field="risk_score",
    key_field="endpoint_name",
)

# Backward-compatible re-exports
APIType = APIExposureAnalyzer.APIType
ExposureLevel = APIExposureAnalyzer.ExposureLevel
APIRisk = APIExposureAnalyzer.APIRisk
APIExposureRecord = APIExposureAnalyzer.Record
APIExposureAnalysis = APIExposureAnalyzer.Analysis
APIExposureReport = APIExposureAnalyzer.Report
