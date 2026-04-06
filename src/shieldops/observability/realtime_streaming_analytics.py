"""Realtime Streaming Analytics Streaming telemetry processing, windowed aggregations, late-ar..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RealtimeStreamingAnalytics = engine(
    "RealtimeStreamingAnalytics",
    description="Realtime Streaming Analytics Streaming telemetry processing, windowed aggre...",
    enums={
        "window_type": EnumDef(
            "WindowType",
            {
                "TUMBLING": "tumbling",
                "SLIDING": "sliding",
                "SESSION": "session",
                "HOPPING": "hopping",
                "GLOBAL": "global",
            },
        ),
        "stream_status": EnumDef(
            "StreamStatus",
            {
                "HEALTHY": "healthy",
                "BACKPRESSURE": "backpressure",
                "LAGGING": "lagging",
                "STALLED": "stalled",
                "RECOVERING": "recovering",
            },
        ),
        "arrival_status": EnumDef(
            "ArrivalStatus",
            {
                "ON_TIME": "on_time",
                "LATE": "late",
                "VERY_LATE": "very_late",
                "OUT_OF_ORDER": "out_of_order",
                "DUPLICATE": "duplicate",
            },
        ),
    },
    record_fields=[
        FieldDef("events_per_second", float, 0.0),
        FieldDef("window_duration_sec", float, 60.0),
        FieldDef("watermark_lag_ms", float, 0.0),
        FieldDef("buffer_utilization_pct", float, 0.0),
        FieldDef("late_event_count", int, 0),
        FieldDef("dropped_event_count", int, 0),
        FieldDef("partition", str, ""),
    ],
    key_field="stream_name",
)

# Backward-compatible re-exports
WindowType = RealtimeStreamingAnalytics.WindowType
StreamStatus = RealtimeStreamingAnalytics.StreamStatus
ArrivalStatus = RealtimeStreamingAnalytics.ArrivalStatus
StreamRecord = RealtimeStreamingAnalytics.Record
StreamAnalysis = RealtimeStreamingAnalytics.Analysis
StreamingReport = RealtimeStreamingAnalytics.Report
