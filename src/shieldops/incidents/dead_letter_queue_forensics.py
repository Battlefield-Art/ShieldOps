"""Dead Letter Queue Forensics — classify failure patterns, compute reprocessing success rate,..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DeadLetterQueueForensics = engine(
    "DeadLetterQueueForensics",
    description="Classify failure patterns, compute reprocessing success rate, rank DLQs by...",
    enums={
        "failure_reason": EnumDef(
            "FailureReason",
            {
                "DESERIALIZATION": "deserialization",
                "VALIDATION": "validation",
                "TIMEOUT": "timeout",
                "DEPENDENCY": "dependency",
            },
        ),
        "reprocessing_outcome": EnumDef(
            "ReprocessingOutcome",
            {
                "SUCCESS": "success",
                "PARTIAL": "partial",
                "FAILED": "failed",
                "SKIPPED": "skipped",
            },
        ),
        "urgency_level": EnumDef(
            "UrgencyLevel",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("message_count", int, 0),
        FieldDef("age_hours", float, 0.0),
        FieldDef("source_topic", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="dlq_name",
)

# Backward-compatible re-exports
FailureReason = DeadLetterQueueForensics.FailureReason
ReprocessingOutcome = DeadLetterQueueForensics.ReprocessingOutcome
UrgencyLevel = DeadLetterQueueForensics.UrgencyLevel
DlqRecord = DeadLetterQueueForensics.Record
DlqAnalysis = DeadLetterQueueForensics.Analysis
DlqReport = DeadLetterQueueForensics.Report
