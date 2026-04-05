"""Alert Risk Enrichment Engine enrich alerts with risk context, compute enrichment completene..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AlertRiskEnrichmentEngine = engine(
    "AlertRiskEnrichmentEngine",
    description="Enrich alerts with risk context, compute enrichment completeness, detect st...",
    enums={
        "source": EnumDef(
            "EnrichmentSource",
            {
                "ASSET_CONTEXT": "asset_context",
                "USER_CONTEXT": "user_context",
                "THREAT_INTEL": "threat_intel",
                "HISTORY": "history",
            },
        ),
        "quality": EnumDef(
            "EnrichmentQuality",
            {
                "COMPLETE": "complete",
                "PARTIAL": "partial",
                "STALE": "stale",
                "UNAVAILABLE": "unavailable",
            },
        ),
        "fidelity": EnumDef(
            "AlertFidelity",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "NOISE": "noise",
            },
        ),
    },
    record_fields=[
        FieldDef("staleness_hours", float, 0.0),
        FieldDef("entity_id", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="enrichment_score",
    key_field="alert_id",
)

# Backward-compatible re-exports
EnrichmentSource = AlertRiskEnrichmentEngine.EnrichmentSource
EnrichmentQuality = AlertRiskEnrichmentEngine.EnrichmentQuality
AlertFidelity = AlertRiskEnrichmentEngine.AlertFidelity
AlertEnrichmentRecord = AlertRiskEnrichmentEngine.Record
AlertEnrichmentAnalysis = AlertRiskEnrichmentEngine.Analysis
AlertEnrichmentReport = AlertRiskEnrichmentEngine.Report
