"""OtelPipelineThroughputEngine — Monitor and optimize OTel pipeline throughput per signal type."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OtelPipelineThroughputEngine = engine(
    "OtelPipelineThroughputEngine",
    description="Monitor and optimize OTel pipeline throughput per signal type.",
    enums={
        "signal_type": EnumDef(
            "SignalType",
            {
                "TRACES": "traces",
                "METRICS": "metrics",
                "LOGS": "logs",
            },
        ),
        "throughput_status": EnumDef(
            "ThroughputStatus",
            {
                "NORMAL": "normal",
                "THROTTLED": "throttled",
                "BACKPRESSURED": "backpressured",
                "DROPPING": "dropping",
            },
        ),
        "bottleneck_location": EnumDef(
            "BottleneckLocation",
            {
                "RECEIVER": "receiver",
                "PROCESSOR": "processor",
                "EXPORTER": "exporter",
            },
        ),
    },
    record_fields=[
        FieldDef("events_per_second", float, 0.0),
        FieldDef("drop_rate", float, 0.0),
    ],
)

# Backward-compatible re-exports
SignalType = OtelPipelineThroughputEngine.SignalType
ThroughputStatus = OtelPipelineThroughputEngine.ThroughputStatus
BottleneckLocation = OtelPipelineThroughputEngine.BottleneckLocation
OtelPipelineThroughputRecord = OtelPipelineThroughputEngine.Record
OtelPipelineThroughputAnalysis = OtelPipelineThroughputEngine.Analysis
OtelPipelineThroughputReport = OtelPipelineThroughputEngine.Report
