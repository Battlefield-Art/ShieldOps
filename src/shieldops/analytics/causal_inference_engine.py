"""Causal Inference Engine Evaluates causal relationships between operational events using cou..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CausalInferenceEngine = engine(
    "CausalInferenceEngine",
    description="Causal Inference Engine Evaluates causal relationships between operational...",
    enums={
        "relation": EnumDef(
            "CausalRelation",
            {
                "CAUSES": "causes",
                "CORRELATES": "correlates",
                "PRECEDES": "precedes",
                "INDEPENDENT": "independent",
                "UNKNOWN": "unknown",
            },
        ),
        "evidence_strength": EnumDef(
            "EvidenceStrength",
            {
                "STRONG": "strong",
                "MODERATE": "moderate",
                "WEAK": "weak",
                "INSUFFICIENT": "insufficient",
            },
        ),
        "intervention_type": EnumDef(
            "InterventionType",
            {
                "DEPLOYMENT": "deployment",
                "CONFIG_CHANGE": "config_change",
                "SCALING": "scaling",
                "RESTART": "restart",
                "EXTERNAL": "external",
            },
        ),
    },
    record_fields=[
        FieldDef("target_event", str, ""),
        FieldDef("temporal_lag_sec", float, 0.0),
        FieldDef("blast_radius_overlap", float, 0.0),
    ],
    score_field="confidence_score",
    key_field="source_event",
)

# Backward-compatible re-exports
CausalRelation = CausalInferenceEngine.CausalRelation
EvidenceStrength = CausalInferenceEngine.EvidenceStrength
InterventionType = CausalInferenceEngine.InterventionType
CausalRecord = CausalInferenceEngine.Record
CausalAnalysis = CausalInferenceEngine.Analysis
CausalReport = CausalInferenceEngine.Report
