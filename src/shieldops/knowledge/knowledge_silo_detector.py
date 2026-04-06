"""Knowledge Silo Detector — identify knowledge silos, compute bus factor, rank domains by con..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

KnowledgeSiloDetector = engine(
    "KnowledgeSiloDetector",
    description="Identify knowledge silos, compute bus factor, rank domains by concentration...",
    enums={
        "area": EnumDef(
            "KnowledgeArea",
            {
                "CODEBASE": "codebase",
                "INFRASTRUCTURE": "infrastructure",
                "PROCESS": "process",
                "DOMAIN": "domain",
            },
        ),
        "risk": EnumDef(
            "SiloRisk",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "concentration": EnumDef(
            "ConcentrationType",
            {
                "SINGLE_PERSON": "single_person",
                "SMALL_GROUP": "small_group",
                "DISTRIBUTED": "distributed",
                "DOCUMENTED": "documented",
            },
        ),
    },
    record_fields=[
        FieldDef("person_id", str, ""),
        FieldDef("expertise_level", float, 0.0),
        FieldDef("contribution_count", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="domain_id",
)

# Backward-compatible re-exports
KnowledgeArea = KnowledgeSiloDetector.KnowledgeArea
SiloRisk = KnowledgeSiloDetector.SiloRisk
ConcentrationType = KnowledgeSiloDetector.ConcentrationType
KnowledgeSiloRecord = KnowledgeSiloDetector.Record
KnowledgeSiloAnalysis = KnowledgeSiloDetector.Analysis
KnowledgeSiloReport = KnowledgeSiloDetector.Report
