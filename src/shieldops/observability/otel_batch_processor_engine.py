"""OtelBatchProcessorEngine — Monitor and tune OTel batch processor performance."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OtelBatchProcessorEngine = engine(
    "OtelBatchProcessorEngine",
    description="Monitor and tune OTel batch processor performance engine.",
    enums={
        "batch_status": EnumDef(
            "BatchStatus",
            {
                "HEALTHY": "healthy",
                "FULL": "full",
                "DROPPING": "dropping",
                "STALLED": "stalled",
            },
        ),
        "queue_pressure": EnumDef(
            "QueuePressure",
            {
                "LOW": "low",
                "MODERATE": "moderate",
                "HIGH": "high",
                "CRITICAL": "critical",
            },
        ),
        "tuning_action": EnumDef(
            "TuningAction",
            {
                "INCREASE_BATCH_SIZE": "increase_batch_size",
                "DECREASE_TIMEOUT": "decrease_timeout",
                "ADD_MEMORY": "add_memory",
                "SCALE_OUT": "scale_out",
            },
        ),
    },
    record_fields=[
        FieldDef("batch_size", int, 512),
        FieldDef("queue_depth", int, 0),
        FieldDef("queue_capacity", int, 2048),
        FieldDef("dropped_spans", int, 0),
    ],
)

# Backward-compatible re-exports
BatchStatus = OtelBatchProcessorEngine.BatchStatus
QueuePressure = OtelBatchProcessorEngine.QueuePressure
TuningAction = OtelBatchProcessorEngine.TuningAction
OtelBatchProcessorRecord = OtelBatchProcessorEngine.Record
OtelBatchProcessorAnalysis = OtelBatchProcessorEngine.Analysis
OtelBatchProcessorReport = OtelBatchProcessorEngine.Report
