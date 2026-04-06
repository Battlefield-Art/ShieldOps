"""Agent Transfer Learning Engine — evaluate domain similarity, measure transfer effectiveness..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentTransferLearningEngine = engine(
    "AgentTransferLearningEngine",
    description="Transfer knowledge between agent domains, evaluate domain similarity, and r...",
    enums={
        "transfer_type": EnumDef(
            "TransferType",
            {
                "DIRECT": "direct",
                "FINE_TUNED": "fine_tuned",
                "ADAPTED": "adapted",
                "ZERO_SHOT": "zero_shot",
            },
        ),
        "domain_similarity": EnumDef(
            "DomainSimilarity",
            {
                "IDENTICAL": "identical",
                "SIMILAR": "similar",
                "RELATED": "related",
                "DISTANT": "distant",
            },
        ),
        "outcome": EnumDef(
            "TransferOutcome",
            {
                "POSITIVE": "positive",
                "NEUTRAL": "neutral",
                "NEGATIVE": "negative",
                "CATASTROPHIC": "catastrophic",
            },
        ),
    },
    record_fields=[
        FieldDef("target_agent", str, ""),
        FieldDef("performance_delta", float, 0.0),
        FieldDef("convergence_speed", float, 0.0),
        FieldDef("knowledge_retained", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="source_agent",
)

# Backward-compatible re-exports
TransferType = AgentTransferLearningEngine.TransferType
DomainSimilarity = AgentTransferLearningEngine.DomainSimilarity
TransferOutcome = AgentTransferLearningEngine.TransferOutcome
TransferLearningRecord = AgentTransferLearningEngine.Record
TransferLearningAnalysis = AgentTransferLearningEngine.Analysis
TransferLearningReport = AgentTransferLearningEngine.Report
