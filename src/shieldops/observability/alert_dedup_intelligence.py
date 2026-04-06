"""Alert Dedup Intelligence compute dedup fingerprints, identify duplicate clusters, measure d..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AlertDedupIntelligence = engine(
    "AlertDedupIntelligence",
    description="Compute dedup fingerprints, identify duplicate clusters, measure dedup effe...",
    enums={
        "dedup_strategy": EnumDef(
            "DedupStrategy",
            {
                "FINGERPRINT": "fingerprint",
                "SEMANTIC": "semantic",
                "TEMPORAL": "temporal",
                "HYBRID": "hybrid",
            },
        ),
        "cluster_status": EnumDef(
            "ClusterStatus",
            {
                "ACTIVE": "active",
                "MERGED": "merged",
                "RESOLVED": "resolved",
                "STALE": "stale",
            },
        ),
        "similarity_level": EnumDef(
            "SimilarityLevel",
            {
                "EXACT": "exact",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("fingerprint", str, ""),
        FieldDef("cluster_id", str, ""),
        FieldDef("source", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="alert_id",
)

# Backward-compatible re-exports
DedupStrategy = AlertDedupIntelligence.DedupStrategy
ClusterStatus = AlertDedupIntelligence.ClusterStatus
SimilarityLevel = AlertDedupIntelligence.SimilarityLevel
AlertDedupRecord = AlertDedupIntelligence.Record
AlertDedupAnalysis = AlertDedupIntelligence.Analysis
AlertDedupReport = AlertDedupIntelligence.Report
