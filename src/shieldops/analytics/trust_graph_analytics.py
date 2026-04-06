"""Trust Graph Analytics — analyze identity trust graphs."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TrustGraphAnalyticsEngine = engine(
    "TrustGraphAnalyticsEngine",
    description="Analyze identity trust graph structure.",
    enums={
        "metric": EnumDef(
            "GraphMetric",
            {
                "DENSITY": "density",
                "DIAMETER": "diameter",
                "CENTRALITY": "centrality",
                "CLUSTERING": "clustering",
            },
        ),
        "density": EnumDef(
            "TrustDensity",
            {
                "OVER_CONNECTED": "over_connected",
                "BALANCED": "balanced",
                "SPARSE": "sparse",
                "ISOLATED": "isolated",
            },
        ),
        "abuse_pattern": EnumDef(
            "AbusePattern",
            {
                "FEDERATION_ABUSE": "federation_abuse",
                "DELEGATION_CHAIN": "delegation_chain",
                "CROSS_ACCOUNT_PIVOT": "cross_account_pivot",
            },
        ),
    },
    record_fields=[
        FieldDef("target_entity", str, ""),
        FieldDef("trust_type", str, ""),
        FieldDef("edge_count", int, 0),
        FieldDef("node_count", int, 0),
    ],
    score_field="risk_score",
    key_field="source_entity",
)

# Backward-compatible re-exports
GraphMetric = TrustGraphAnalyticsEngine.GraphMetric
TrustDensity = TrustGraphAnalyticsEngine.TrustDensity
AbusePattern = TrustGraphAnalyticsEngine.AbusePattern
TrustGraphRecord = TrustGraphAnalyticsEngine.Record
TrustGraphAnalysis = TrustGraphAnalyticsEngine.Analysis
TrustGraphReport = TrustGraphAnalyticsEngine.Report
