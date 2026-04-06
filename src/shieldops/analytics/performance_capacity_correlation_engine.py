"""Performance Capacity Correlation Engine compute capacity-performance correlation, detect ca..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

PerformanceCapacityCorrelationEngine = engine(
    "PerformanceCapacityCorrelationEngine",
    description="Compute capacity-performance correlation, detect capacity driven degradatio...",
    enums={
        "correlation_strength": EnumDef(
            "CorrelationStrength",
            {
                "STRONG": "strong",
                "MODERATE": "moderate",
                "WEAK": "weak",
                "NONE": "none",
            },
        ),
        "capacity_metric": EnumDef(
            "CapacityMetric",
            {
                "CPU_UTILIZATION": "cpu_utilization",
                "MEMORY_PRESSURE": "memory_pressure",
                "DISK_IO": "disk_io",
                "NETWORK_BANDWIDTH": "network_bandwidth",
            },
        ),
        "performance_metric": EnumDef(
            "PerformanceMetric",
            {
                "LATENCY": "latency",
                "THROUGHPUT": "throughput",
                "ERROR_RATE": "error_rate",
                "AVAILABILITY": "availability",
            },
        ),
    },
    record_fields=[
        FieldDef("capacity_value", float, 0.0),
        FieldDef("performance_value", float, 0.0),
        FieldDef("correlation_coefficient", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="resource_id",
)

# Backward-compatible re-exports
CorrelationStrength = PerformanceCapacityCorrelationEngine.CorrelationStrength
CapacityMetric = PerformanceCapacityCorrelationEngine.CapacityMetric
PerformanceMetric = PerformanceCapacityCorrelationEngine.PerformanceMetric
PerformanceCapacityRecord = PerformanceCapacityCorrelationEngine.Record
PerformanceCapacityAnalysis = PerformanceCapacityCorrelationEngine.Analysis
PerformanceCapacityReport = PerformanceCapacityCorrelationEngine.Report
