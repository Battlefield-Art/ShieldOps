"""Kafka OTel Bridge Engine — evaluate bridge throughput, detect mapping drift, rank topics by..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

KafkaOtelBridgeEngine = engine(
    "KafkaOtelBridgeEngine",
    description="Evaluate bridge throughput, detect mapping drift, rank topics by signal value.",
    enums={
        "bridge_mode": EnumDef(
            "BridgeMode",
            {
                "PASSTHROUGH": "passthrough",
                "TRANSFORM": "transform",
                "ENRICH": "enrich",
                "AGGREGATE": "aggregate",
            },
        ),
        "signal_mapping": EnumDef(
            "SignalMapping",
            {
                "MESSAGE_TO_SPAN": "message_to_span",
                "MESSAGE_TO_METRIC": "message_to_metric",
                "MESSAGE_TO_LOG": "message_to_log",
                "MESSAGE_TO_EVENT": "message_to_event",
            },
        ),
        "bridge_fidelity": EnumDef(
            "BridgeFidelity",
            {
                "EXACT": "exact",
                "LOSSY": "lossy",
                "SAMPLED": "sampled",
                "COMPRESSED": "compressed",
            },
        ),
    },
    record_fields=[
        FieldDef("messages_per_sec", float, 0.0),
        FieldDef("mapping_drift_pct", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="signal_value_score",
    key_field="topic",
)

# Backward-compatible re-exports
BridgeMode = KafkaOtelBridgeEngine.BridgeMode
SignalMapping = KafkaOtelBridgeEngine.SignalMapping
BridgeFidelity = KafkaOtelBridgeEngine.BridgeFidelity
KafkaOtelBridgeRecord = KafkaOtelBridgeEngine.Record
KafkaOtelBridgeAnalysis = KafkaOtelBridgeEngine.Analysis
KafkaOtelBridgeReport = KafkaOtelBridgeEngine.Report
