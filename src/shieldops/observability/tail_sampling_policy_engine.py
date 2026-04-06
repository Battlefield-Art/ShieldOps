"""TailSamplingPolicyEngine — Manage and optimize tail-based sampling policies."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TailSamplingPolicyEngine = engine(
    "TailSamplingPolicyEngine",
    description="Manage and optimize tail-based sampling policies engine.",
    enums={
        "policy_decision": EnumDef(
            "PolicyDecision",
            {
                "ALWAYS_SAMPLE": "always_sample",
                "PROBABILISTIC": "probabilistic",
                "RATE_LIMIT": "rate_limit",
            },
        ),
        "sampling_criteria": EnumDef(
            "SamplingCriteria",
            {
                "LATENCY": "latency",
                "ERROR": "error",
                "ATTRIBUTE": "attribute",
                "COMPOSITE": "composite",
            },
        ),
        "policy_effectiveness": EnumDef(
            "PolicyEffectiveness",
            {
                "OPTIMAL": "optimal",
                "OVERSAMPLING": "oversampling",
                "UNDERSAMPLING": "undersampling",
            },
        ),
    },
    record_fields=[
        FieldDef("sample_rate", float, 1.0),
        FieldDef("spans_evaluated", int, 0),
        FieldDef("spans_sampled", int, 0),
    ],
)

# Backward-compatible re-exports
PolicyDecision = TailSamplingPolicyEngine.PolicyDecision
SamplingCriteria = TailSamplingPolicyEngine.SamplingCriteria
PolicyEffectiveness = TailSamplingPolicyEngine.PolicyEffectiveness
TailSamplingPolicyRecord = TailSamplingPolicyEngine.Record
TailSamplingPolicyAnalysis = TailSamplingPolicyEngine.Analysis
TailSamplingPolicyReport = TailSamplingPolicyEngine.Report
