"""Escalation Path Optimizer analyze escalation efficiency, detect antipatterns, recommend pat..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EscalationPathOptimizer = engine(
    "EscalationPathOptimizer",
    description="Analyze escalation efficiency, detect antipatterns, recommend path restruct...",
    enums={
        "escalation_outcome": EnumDef(
            "EscalationOutcome",
            {
                "RESOLVED": "resolved",
                "REROUTED": "rerouted",
                "TIMED_OUT": "timed_out",
                "ABANDONED": "abandoned",
            },
        ),
        "path_type": EnumDef(
            "PathType",
            {
                "LINEAR": "linear",
                "SKIP_LEVEL": "skip_level",
                "PARALLEL": "parallel",
                "HYBRID": "hybrid",
            },
        ),
        "antipattern_type": EnumDef(
            "AntipatternType",
            {
                "PINGPONG": "pingpong",
                "DEAD_END": "dead_end",
                "BOTTLENECK": "bottleneck",
                "SKIP_ABUSE": "skip_abuse",
            },
        ),
    },
    record_fields=[
        FieldDef("hops", int, 0),
        FieldDef("total_time_min", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="incident_id",
)

# Backward-compatible re-exports
EscalationOutcome = EscalationPathOptimizer.EscalationOutcome
PathType = EscalationPathOptimizer.PathType
AntipatternType = EscalationPathOptimizer.AntipatternType
EscalationPathRecord = EscalationPathOptimizer.Record
EscalationPathAnalysis = EscalationPathOptimizer.Analysis
EscalationPathReport = EscalationPathOptimizer.Report
