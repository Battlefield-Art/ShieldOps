"""Trace Bottleneck Analyzer Critical path analysis, bottleneck identification, latency attrib..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TraceBottleneckAnalyzer = engine(
    "TraceBottleneckAnalyzer",
    description="Trace Bottleneck Analyzer Critical path analysis, bottleneck identification...",
    enums={
        "span_kind": EnumDef(
            "SpanKind",
            {
                "CLIENT": "client",
                "SERVER": "server",
                "PRODUCER": "producer",
                "CONSUMER": "consumer",
                "INTERNAL": "internal",
            },
        ),
        "bottleneck_type": EnumDef(
            "BottleneckType",
            {
                "SLOW_QUERY": "slow_query",
                "NETWORK_LATENCY": "network_latency",
                "SERIALIZATION": "serialization",
                "LOCK_CONTENTION": "lock_contention",
                "RESOURCE_EXHAUSTION": "resource_exhaustion",
                "EXTERNAL_DEPENDENCY": "external_dependency",
                "CPU_BOUND": "cpu_bound",
                "IO_WAIT": "io_wait",
            },
        ),
        "optimization_priority": EnumDef(
            "OptimizationPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "INFORMATIONAL": "informational",
            },
        ),
    },
    record_fields=[
        FieldDef("span_id", str, ""),
        FieldDef("parent_span_id", str, ""),
        FieldDef("operation_name", str, ""),
        FieldDef("duration_ms", float, 0.0),
        FieldDef("self_time_ms", float, 0.0),
        FieldDef("child_count", int, 0),
        FieldDef("is_critical_path", bool, False),
        FieldDef("is_bottleneck", bool, False),
        FieldDef("error", bool, False),
    ],
    key_field="trace_id",
)

# Backward-compatible re-exports
SpanKind = TraceBottleneckAnalyzer.SpanKind
BottleneckType = TraceBottleneckAnalyzer.BottleneckType
OptimizationPriority = TraceBottleneckAnalyzer.OptimizationPriority
TraceSpanRecord = TraceBottleneckAnalyzer.Record
BottleneckAnalysis = TraceBottleneckAnalyzer.Analysis
TraceBottleneckReport = TraceBottleneckAnalyzer.Report
