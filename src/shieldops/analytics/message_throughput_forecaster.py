"""Message Throughput Forecaster — forecast throughput demand, detect bottlenecks, rank topics..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MessageThroughputForecaster = engine(
    "MessageThroughputForecaster",
    description="Forecast throughput demand, detect bottlenecks, rank topics by scaling urge...",
    enums={
        "forecast_window": EnumDef(
            "ForecastWindow",
            {
                "HOURLY": "hourly",
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
            },
        ),
        "bottleneck_type": EnumDef(
            "BottleneckType",
            {
                "PRODUCER": "producer",
                "BROKER": "broker",
                "CONSUMER": "consumer",
                "NETWORK": "network",
            },
        ),
        "scaling_urgency": EnumDef(
            "ScalingUrgency",
            {
                "IMMEDIATE": "immediate",
                "SOON": "soon",
                "PLANNED": "planned",
                "NONE": "none",
            },
        ),
    },
    record_fields=[
        FieldDef("current_throughput", float, 0.0),
        FieldDef("peak_throughput", float, 0.0),
        FieldDef("capacity_pct", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="topic_name",
)

# Backward-compatible re-exports
ForecastWindow = MessageThroughputForecaster.ForecastWindow
BottleneckType = MessageThroughputForecaster.BottleneckType
ScalingUrgency = MessageThroughputForecaster.ScalingUrgency
ThroughputRecord = MessageThroughputForecaster.Record
ThroughputAnalysis = MessageThroughputForecaster.Analysis
ThroughputReport = MessageThroughputForecaster.Report
