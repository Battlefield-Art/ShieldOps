"""Event Processing Latency Profiler — profile end-to-end latency, detect outliers, rank pipel..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EventProcessingLatencyProfiler = engine(
    "EventProcessingLatencyProfiler",
    description="Profile end-to-end latency, detect outliers, rank pipelines by latency risk.",
    enums={
        "processing_stage": EnumDef(
            "ProcessingStage",
            {
                "INGESTION": "ingestion",
                "PROCESSING": "processing",
                "ENRICHMENT": "enrichment",
                "DELIVERY": "delivery",
            },
        ),
        "latency_profile": EnumDef(
            "LatencyProfile",
            {
                "REALTIME": "realtime",
                "NEAR_REALTIME": "near_realtime",
                "BATCH": "batch",
                "DELAYED": "delayed",
            },
        ),
        "outlier_type": EnumDef(
            "OutlierType",
            {
                "SPIKE": "spike",
                "SUSTAINED": "sustained",
                "PERIODIC": "periodic",
                "RANDOM": "random",
            },
        ),
    },
    record_fields=[
        FieldDef("latency_ms", float, 0.0),
        FieldDef("p99_latency_ms", float, 0.0),
        FieldDef("throughput", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="pipeline_id",
)

# Backward-compatible re-exports
ProcessingStage = EventProcessingLatencyProfiler.ProcessingStage
LatencyProfile = EventProcessingLatencyProfiler.LatencyProfile
OutlierType = EventProcessingLatencyProfiler.OutlierType
LatencyRecord = EventProcessingLatencyProfiler.Record
LatencyAnalysis = EventProcessingLatencyProfiler.Analysis
LatencyReport = EventProcessingLatencyProfiler.Report
