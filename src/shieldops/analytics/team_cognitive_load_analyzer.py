"""Team Cognitive Load Analyzer — compute cognitive load index, detect overload patterns, rank..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TeamCognitiveLoadAnalyzer = engine(
    "TeamCognitiveLoadAnalyzer",
    description="Compute cognitive load index, detect overload, rank teams by load sustainab...",
    enums={
        "load_type": EnumDef(
            "LoadType",
            {
                "INTRINSIC": "intrinsic",
                "EXTRANEOUS": "extraneous",
                "GERMANE": "germane",
                "OPERATIONAL": "operational",
            },
        ),
        "level": EnumDef(
            "LoadLevel",
            {
                "SUSTAINABLE": "sustainable",
                "ELEVATED": "elevated",
                "HIGH": "high",
                "OVERLOADED": "overloaded",
            },
        ),
        "source": EnumDef(
            "LoadSource",
            {
                "SYSTEM_COMPLEXITY": "system_complexity",
                "PROCESS_OVERHEAD": "process_overhead",
                "CONTEXT_SWITCHING": "context_switching",
                "INCIDENT_BURDEN": "incident_burden",
            },
        ),
    },
    record_fields=[
        FieldDef("services_owned", int, 0),
        FieldDef("context_switches", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="load_score",
    key_field="team_id",
)

# Backward-compatible re-exports
LoadType = TeamCognitiveLoadAnalyzer.LoadType
LoadLevel = TeamCognitiveLoadAnalyzer.LoadLevel
LoadSource = TeamCognitiveLoadAnalyzer.LoadSource
CognitiveLoadRecord = TeamCognitiveLoadAnalyzer.Record
CognitiveLoadAnalysis = TeamCognitiveLoadAnalyzer.Analysis
CognitiveLoadReport = TeamCognitiveLoadAnalyzer.Report
