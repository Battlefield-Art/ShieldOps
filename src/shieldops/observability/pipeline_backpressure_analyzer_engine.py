"""Pipeline Backpressure Analyzer Engine — trace backpressure source, measure queue drain rate..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

PipelineBackpressureAnalyzerEngine = engine(
    "PipelineBackpressureAnalyzerEngine",
    description="Trace backpressure source, measure queue drain rate, simulate load shed imp...",
    enums={
        "pipeline_stage": EnumDef(
            "PipelineStage",
            {
                "RECEIVER": "receiver",
                "PROCESSOR": "processor",
                "EXPORTER": "exporter",
                "INTERNAL_QUEUE": "internal_queue",
            },
        ),
        "backpressure_level": EnumDef(
            "BackpressureLevel",
            {
                "NONE": "none",
                "MILD": "mild",
                "SEVERE": "severe",
                "CRITICAL": "critical",
            },
        ),
        "propagation_direction": EnumDef(
            "PropagationDirection",
            {
                "DOWNSTREAM": "downstream",
                "UPSTREAM": "upstream",
                "BIDIRECTIONAL": "bidirectional",
                "ISOLATED": "isolated",
            },
        ),
    },
    record_fields=[
        FieldDef("queue_depth", int, 0),
        FieldDef("queue_capacity", int, 1),
        FieldDef("drain_rate_per_sec", float, 0.0),
        FieldDef("fill_rate_per_sec", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="pipeline_id",
)

# Backward-compatible re-exports
PipelineStage = PipelineBackpressureAnalyzerEngine.PipelineStage
BackpressureLevel = PipelineBackpressureAnalyzerEngine.BackpressureLevel
PropagationDirection = PipelineBackpressureAnalyzerEngine.PropagationDirection
PipelineBackpressureRecord = PipelineBackpressureAnalyzerEngine.Record
PipelineBackpressureAnalysis = PipelineBackpressureAnalyzerEngine.Analysis
PipelineBackpressureReport = PipelineBackpressureAnalyzerEngine.Report
