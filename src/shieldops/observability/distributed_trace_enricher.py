"""Distributed Trace Enricher — distributed trace enrichment and context propagation."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

DistributedTraceEnricher = engine(
    "DistributedTraceEnricher",
    description="Distributed Trace Enricher — distributed trace enrichment and context propa...",
    enums={
        "enrichment_type": EnumDef(
            "EnrichmentType",
            {
                "SERVICE_CONTEXT": "service_context",
                "INFRASTRUCTURE": "infrastructure",
                "BUSINESS": "business",
                "SECURITY": "security",
                "DEPENDENCY": "dependency",
            },
        ),
        "enrichment_source": EnumDef(
            "EnrichmentSource",
            {
                "OTEL_SDK": "otel_sdk",
                "JAEGER": "jaeger",
                "ZIPKIN": "zipkin",
                "CLOUD_TRACE": "cloud_trace",
                "CUSTOM": "custom",
            },
        ),
        "enrichment_quality": EnumDef(
            "EnrichmentQuality",
            {
                "COMPLETE": "complete",
                "PARTIAL": "partial",
                "MINIMAL": "minimal",
                "MISSING": "missing",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
EnrichmentType = DistributedTraceEnricher.EnrichmentType
EnrichmentSource = DistributedTraceEnricher.EnrichmentSource
EnrichmentQuality = DistributedTraceEnricher.EnrichmentQuality
EnrichmentRecord = DistributedTraceEnricher.Record
EnrichmentAnalysis = DistributedTraceEnricher.Analysis
DistributedTraceReport = DistributedTraceEnricher.Report
