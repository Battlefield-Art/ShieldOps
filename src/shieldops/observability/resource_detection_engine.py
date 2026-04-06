"""ResourceDetectionEngine — resource attribute detection."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ResourceDetectionEngine = engine(
    "ResourceDetectionEngine",
    description="Resource attribute detection engine.",
    enums={
        "resource_provider": EnumDef(
            "ResourceProvider",
            {
                "AWS": "aws",
                "GCP": "gcp",
                "AZURE": "azure",
                "KUBERNETES": "kubernetes",
            },
        ),
        "detection_method": EnumDef(
            "DetectionMethod",
            {
                "API_CALL": "api_call",
                "ENV_VAR": "env_var",
                "METADATA": "metadata",
                "FILE_SYSTEM": "file_system",
            },
        ),
        "resource_confidence": EnumDef(
            "ResourceConfidence",
            {
                "VERIFIED": "verified",
                "PROBABLE": "probable",
                "INFERRED": "inferred",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
ResourceProvider = ResourceDetectionEngine.ResourceProvider
DetectionMethod = ResourceDetectionEngine.DetectionMethod
ResourceConfidence = ResourceDetectionEngine.ResourceConfidence
ResourceDetectionEngineRecord = ResourceDetectionEngine.Record
ResourceDetectionEngineAnalysis = ResourceDetectionEngine.Analysis
ResourceDetectionEngineReport = ResourceDetectionEngine.Report
