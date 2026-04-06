"""Message Ordering Guarantee Tracker — detect ordering violations, compute consistency score,..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MessageOrderingGuaranteeTracker = engine(
    "MessageOrderingGuaranteeTracker",
    description="Detect ordering violations, compute consistency score, rank consumers by or...",
    enums={
        "ordering_guarantee": EnumDef(
            "OrderingGuarantee",
            {
                "STRICT": "strict",
                "PARTITION": "partition",
                "CAUSAL": "causal",
                "NONE": "none",
            },
        ),
        "violation_type": EnumDef(
            "ViolationType",
            {
                "REORDER": "reorder",
                "DUPLICATE": "duplicate",
                "GAP": "gap",
                "TIMESTAMP_SKEW": "timestamp_skew",
            },
        ),
        "consistency_level": EnumDef(
            "ConsistencyLevel",
            {
                "PERFECT": "perfect",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("violation_count", int, 0),
        FieldDef("message_count", int, 0),
        FieldDef("topic", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="consumer_id",
)

# Backward-compatible re-exports
OrderingGuarantee = MessageOrderingGuaranteeTracker.OrderingGuarantee
ViolationType = MessageOrderingGuaranteeTracker.ViolationType
ConsistencyLevel = MessageOrderingGuaranteeTracker.ConsistencyLevel
OrderingRecord = MessageOrderingGuaranteeTracker.Record
OrderingAnalysis = MessageOrderingGuaranteeTracker.Analysis
OrderingReport = MessageOrderingGuaranteeTracker.Report
