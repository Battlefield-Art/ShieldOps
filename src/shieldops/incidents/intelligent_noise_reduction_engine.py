"""Intelligent Noise Reduction Engine Clusters and deduplicates related alerts using semantic,..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IntelligentNoiseReductionEngine = engine(
    "IntelligentNoiseReductionEngine",
    description="Intelligent Noise Reduction Engine Clusters and deduplicates related alerts...",
    enums={
        "cluster_method": EnumDef(
            "ClusterMethod",
            {
                "SEMANTIC": "semantic",
                "TEMPORAL": "temporal",
                "TOPOLOGICAL": "topological",
                "OWNERSHIP": "ownership",
                "COMPOSITE": "composite",
            },
        ),
        "noise_category": EnumDef(
            "NoiseCategory",
            {
                "DUPLICATE": "duplicate",
                "TRANSIENT": "transient",
                "CASCADING": "cascading",
                "INFORMATIONAL": "informational",
                "ACTIONABLE": "actionable",
            },
        ),
        "reduction_outcome": EnumDef(
            "ReductionOutcome",
            {
                "MERGED": "merged",
                "SUPPRESSED": "suppressed",
                "ESCALATED": "escalated",
                "RETAINED": "retained",
            },
        ),
    },
    record_fields=[
        FieldDef("cluster_id", str, ""),
        FieldDef("original_severity", str, ""),
        FieldDef("adjusted_severity", str, ""),
    ],
    score_field="similarity_score",
    key_field="alert_id",
)

# Backward-compatible re-exports
ClusterMethod = IntelligentNoiseReductionEngine.ClusterMethod
NoiseCategory = IntelligentNoiseReductionEngine.NoiseCategory
ReductionOutcome = IntelligentNoiseReductionEngine.ReductionOutcome
NoiseReductionRecord = IntelligentNoiseReductionEngine.Record
NoiseReductionAnalysis = IntelligentNoiseReductionEngine.Analysis
NoiseReductionReport = IntelligentNoiseReductionEngine.Report
