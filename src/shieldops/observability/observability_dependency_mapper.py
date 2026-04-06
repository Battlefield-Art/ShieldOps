"""ObservabilityDependencyMapper — signal deps."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ObservabilityDependencyMapper = engine(
    "ObservabilityDependencyMapper",
    description="Observability Dependency Mapper. Maps dependencies between observability si...",
    enums={
        "signal_type": EnumDef(
            "SignalType",
            {
                "METRIC": "metric",
                "LOG": "log",
                "TRACE": "trace",
                "EVENT": "event",
            },
        ),
        "direction": EnumDef(
            "DependencyDirection",
            {
                "UPSTREAM": "upstream",
                "DOWNSTREAM": "downstream",
                "BIDIRECTIONAL": "bidirectional",
            },
        ),
        "health_impact": EnumDef(
            "HealthImpact",
            {
                "BLOCKING": "blocking",
                "DEGRADING": "degrading",
                "INFORMATIONAL": "informational",
            },
        ),
    },
    record_fields=[
        FieldDef("source_service", str, ""),
        FieldDef("target_service", str, ""),
    ],
)

# Backward-compatible re-exports
SignalType = ObservabilityDependencyMapper.SignalType
DependencyDirection = ObservabilityDependencyMapper.DependencyDirection
HealthImpact = ObservabilityDependencyMapper.HealthImpact
DependencyRecord = ObservabilityDependencyMapper.Record
DependencyAnalysis = ObservabilityDependencyMapper.Analysis
DependencyReport = ObservabilityDependencyMapper.Report
