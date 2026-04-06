"""KafkaTelemetryPipeline — Kafka-OTel pipeline integration."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

KafkaTelemetryPipeline = engine(
    "KafkaTelemetryPipeline",
    description="Kafka-OTel pipeline integration engine.",
    enums={
        "pipeline_stage": EnumDef(
            "PipelineStage",
            {
                "RECEIVER": "receiver",
                "PROCESSOR": "processor",
                "EXPORTER": "exporter",
            },
        ),
        "message_encoding": EnumDef(
            "MessageEncoding",
            {
                "JSON": "json",
                "PROTOBUF": "protobuf",
                "AVRO": "avro",
                "TEXT": "text",
            },
        ),
        "pipeline_health": EnumDef(
            "PipelineHealth",
            {
                "HEALTHY": "healthy",
                "DEGRADED": "degraded",
                "BACKPRESSURE": "backpressure",
                "FAILED": "failed",
            },
        ),
    },
)

# Backward-compatible re-exports
PipelineStage = KafkaTelemetryPipeline.PipelineStage
MessageEncoding = KafkaTelemetryPipeline.MessageEncoding
PipelineHealth = KafkaTelemetryPipeline.PipelineHealth
KafkaTelemetryPipelineRecord = KafkaTelemetryPipeline.Record
KafkaTelemetryPipelineAnalysis = KafkaTelemetryPipeline.Analysis
KafkaTelemetryPipelineReport = KafkaTelemetryPipeline.Report
