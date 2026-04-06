"""OTelKafkaIngestionEngine — track Kafka-based OTel ingestion health."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OTelKafkaIngestionEngine = engine(
    "OTelKafkaIngestionEngine",
    description="Track Kafka-based OTel ingestion — topic throughput, consumer lag, encoding...",
    enums={
        "signal_type": EnumDef(
            "KafkaSignalType",
            {
                "OTLP_PROTO": "otlp_proto",
                "OTLP_JSON": "otlp_json",
                "RAW_JSON": "raw_json",
                "AVRO": "avro",
            },
        ),
        "ingestion_metric": EnumDef(
            "IngestionMetric",
            {
                "THROUGHPUT": "throughput",
                "CONSUMER_LAG": "consumer_lag",
                "ENCODING_ERROR": "encoding_error",
                "PARTITION_SKEW": "partition_skew",
            },
        ),
        "ingestion_status": EnumDef(
            "IngestionStatus",
            {
                "NOMINAL": "nominal",
                "LAGGING": "lagging",
                "ERRORING": "erroring",
                "STALLED": "stalled",
            },
        ),
    },
    record_fields=[
        FieldDef("value", float, 0.0),
        FieldDef("partition_id", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="topic",
)

# Backward-compatible re-exports
KafkaSignalType = OTelKafkaIngestionEngine.KafkaSignalType
IngestionMetric = OTelKafkaIngestionEngine.IngestionMetric
IngestionStatus = OTelKafkaIngestionEngine.IngestionStatus
KafkaIngestionRecord = OTelKafkaIngestionEngine.Record
KafkaIngestionAnalysis = OTelKafkaIngestionEngine.Analysis
KafkaIngestionReport = OTelKafkaIngestionEngine.Report
