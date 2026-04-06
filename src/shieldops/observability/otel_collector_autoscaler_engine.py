"""OTelCollectorAutoscalerEngine — auto-scale OTel collectors based on telemetry volume, queue..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OTelCollectorAutoscalerEngine = engine(
    "OTelCollectorAutoscalerEngine",
    description="Auto-scale OTel collectors based on telemetry volume, queue depth, and reso...",
    enums={
        "scale_direction": EnumDef(
            "ScaleDirection",
            {
                "SCALE_UP": "scale_up",
                "SCALE_DOWN": "scale_down",
                "MAINTAIN": "maintain",
                "EMERGENCY_SCALE": "emergency_scale",
            },
        ),
        "scaling_metric": EnumDef(
            "ScalingMetric",
            {
                "TELEMETRY_VOLUME": "telemetry_volume",
                "QUEUE_DEPTH": "queue_depth",
                "CPU_UTILIZATION": "cpu_utilization",
                "MEMORY_UTILIZATION": "memory_utilization",
            },
        ),
        "scaler_status": EnumDef(
            "ScalerStatus",
            {
                "IDLE": "idle",
                "SCALING": "scaling",
                "COOLDOWN": "cooldown",
                "ERROR": "error",
            },
        ),
    },
    record_fields=[
        FieldDef("value", float, 0.0),
        FieldDef("threshold", float, 0.0),
        FieldDef("replica_count", int, 1),
    ],
    key_field="collector_id",
)

# Backward-compatible re-exports
ScaleDirection = OTelCollectorAutoscalerEngine.ScaleDirection
ScalingMetric = OTelCollectorAutoscalerEngine.ScalingMetric
ScalerStatus = OTelCollectorAutoscalerEngine.ScalerStatus
CollectorAutoscalerRecord = OTelCollectorAutoscalerEngine.Record
CollectorAutoscalerAnalysis = OTelCollectorAutoscalerEngine.Analysis
CollectorAutoscalerReport = OTelCollectorAutoscalerEngine.Report
