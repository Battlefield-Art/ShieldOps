"""Alert Context Enrichment Engine — multi-source enrichment."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AlertContextEnrichmentEngine = engine(
    "AlertContextEnrichmentEngine",
    description="Track contextual enrichment from sources.",
    enums={
        "source": EnumDef(
            "EnrichmentSource",
            {
                "THREAT_FEED": "threat_feed",
                "ASSET_INVENTORY": "asset_inventory",
                "IDENTITY_PROVIDER": "identity_provider",
                "VULNERABILITY_DB": "vulnerability_db",
                "GEO_INTELLIGENCE": "geo_intelligence",
            },
        ),
        "quality": EnumDef(
            "EnrichmentQuality",
            {
                "HIGH_FIDELITY": "high_fidelity",
                "MEDIUM_FIDELITY": "medium_fidelity",
                "LOW_FIDELITY": "low_fidelity",
                "STALE": "stale",
                "UNAVAILABLE": "unavailable",
            },
        ),
        "relevance": EnumDef(
            "ContextRelevance",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
                "IRRELEVANT": "irrelevant",
            },
        ),
    },
    record_fields=[
        FieldDef("enrichment_latency_ms", float, 0.0),
        FieldDef("fields_added", int, 0),
        FieldDef("source_freshness_hours", float, 0.0),
    ],
    key_field="alert_id",
)

# Backward-compatible re-exports
EnrichmentSource = AlertContextEnrichmentEngine.EnrichmentSource
EnrichmentQuality = AlertContextEnrichmentEngine.EnrichmentQuality
ContextRelevance = AlertContextEnrichmentEngine.ContextRelevance
ContextEnrichmentRecord = AlertContextEnrichmentEngine.Record
ContextEnrichmentAnalysis = AlertContextEnrichmentEngine.Analysis
ContextEnrichmentReport = AlertContextEnrichmentEngine.Report
