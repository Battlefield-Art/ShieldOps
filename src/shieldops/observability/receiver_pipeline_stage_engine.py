"""Receiver Pipeline Stage Engine — analyze receiver acceptance rate, detect receiver saturati..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ReceiverPipelineStageEngine = engine(
    "ReceiverPipelineStageEngine",
    description="Analyze receiver acceptance rate, detect receiver saturation, compare recei...",
    enums={
        "receiver_type": EnumDef(
            "ReceiverType",
            {
                "OTLP_GRPC": "otlp_grpc",
                "OTLP_HTTP": "otlp_http",
                "PROMETHEUS": "prometheus",
                "KAFKA": "kafka",
            },
        ),
        "receiver_health": EnumDef(
            "ReceiverHealth",
            {
                "ACCEPTING": "accepting",
                "THROTTLED": "throttled",
                "REJECTING": "rejecting",
                "DISCONNECTED": "disconnected",
            },
        ),
        "ingestion_pattern": EnumDef(
            "IngestionPattern",
            {
                "STEADY": "steady",
                "BURSTY": "bursty",
                "DECLINING": "declining",
                "INTERMITTENT": "intermittent",
            },
        ),
    },
    record_fields=[
        FieldDef("accepted_per_sec", float, 0.0),
        FieldDef("rejected_per_sec", float, 0.0),
        FieldDef("throttle_pct", float, 0.0),
        FieldDef("latency_ms", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="receiver_id",
)

# Backward-compatible re-exports
ReceiverType = ReceiverPipelineStageEngine.ReceiverType
ReceiverHealth = ReceiverPipelineStageEngine.ReceiverHealth
IngestionPattern = ReceiverPipelineStageEngine.IngestionPattern
ReceiverPipelineRecord = ReceiverPipelineStageEngine.Record
ReceiverPipelineAnalysis = ReceiverPipelineStageEngine.Analysis
ReceiverPipelineReport = ReceiverPipelineStageEngine.Report
