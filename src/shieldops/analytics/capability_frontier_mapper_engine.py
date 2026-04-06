"""Capability Frontier Mapper Engine — maps expanding capability boundary of SRE agents."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CapabilityFrontierMapperEngine = engine(
    "CapabilityFrontierMapperEngine",
    description="Maps expanding capability boundary of SRE agents.",
    enums={
        "zone": EnumDef(
            "FrontierZone",
            {
                "MASTERED": "mastered",
                "REACHABLE": "reachable",
                "FRONTIER": "frontier",
                "BEYOND": "beyond",
            },
        ),
        "direction": EnumDef(
            "ExpansionDirection",
            {
                "COMPLEXITY": "complexity",
                "BREADTH": "breadth",
                "DEPTH": "depth",
                "SPECIALIZATION": "specialization",
            },
        ),
        "stability": EnumDef(
            "FrontierStability",
            {
                "STABLE": "stable",
                "EXPANDING": "expanding",
                "CONTRACTING": "contracting",
                "VOLATILE": "volatile",
            },
        ),
    },
    record_fields=[
        FieldDef("capability_name", str, ""),
        FieldDef("expansion_rate", float, 0.0),
        FieldDef("iteration", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="frontier_score",
    key_field="agent_id",
)

# Backward-compatible re-exports
FrontierZone = CapabilityFrontierMapperEngine.FrontierZone
ExpansionDirection = CapabilityFrontierMapperEngine.ExpansionDirection
FrontierStability = CapabilityFrontierMapperEngine.FrontierStability
FrontierRecord = CapabilityFrontierMapperEngine.Record
FrontierAnalysis = CapabilityFrontierMapperEngine.Analysis
FrontierReport = CapabilityFrontierMapperEngine.Report
