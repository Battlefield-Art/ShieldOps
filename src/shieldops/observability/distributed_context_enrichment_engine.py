"""Distributed Context Enrichment Engine — evaluate distributed trace context completeness, de..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DistributedContextEnrichmentEngine = engine(
    "DistributedContextEnrichmentEngine",
    description="Evaluate distributed trace context completeness, detect propagation gaps, o...",
    enums={
        "context_source": EnumDef(
            "ContextSource",
            {
                "BAGGAGE": "baggage",
                "HEADERS": "headers",
                "METADATA": "metadata",
                "ENVIRONMENT": "environment",
            },
        ),
        "enrichment_type": EnumDef(
            "EnrichmentType",
            {
                "BUSINESS": "business",
                "TECHNICAL": "technical",
                "SECURITY": "security",
                "COMPLIANCE": "compliance",
            },
        ),
        "enrichment_quality": EnumDef(
            "EnrichmentQuality",
            {
                "COMPLETE": "complete",
                "PARTIAL": "partial",
                "STALE": "stale",
                "MISSING": "missing",
            },
        ),
    },
    record_fields=[
        FieldDef("service_name", str, ""),
        FieldDef("propagation_hops", int, 0),
        FieldDef("missing_keys", int, 0),
        FieldDef("stale_fields", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="completeness_score",
    key_field="trace_id",
)

# Backward-compatible re-exports
ContextSource = DistributedContextEnrichmentEngine.ContextSource
EnrichmentType = DistributedContextEnrichmentEngine.EnrichmentType
EnrichmentQuality = DistributedContextEnrichmentEngine.EnrichmentQuality
DistributedContextRecord = DistributedContextEnrichmentEngine.Record
DistributedContextAnalysis = DistributedContextEnrichmentEngine.Analysis
DistributedContextReport = DistributedContextEnrichmentEngine.Report
