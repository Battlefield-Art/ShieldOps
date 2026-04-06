"""Operational Knowledge Synthesizer operational knowledge synthesis from incidents and runbooks."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

OperationalKnowledgeSynthesizer = engine(
    "OperationalKnowledgeSynthesizer",
    description="Operational Knowledge Synthesizer operational knowledge synthesis from inci...",
    enums={
        "knowledge_type": EnumDef(
            "KnowledgeType",
            {
                "PATTERN": "pattern",
                "ROOT_CAUSE": "root_cause",
                "SOLUTION": "solution",
                "BEST_PRACTICE": "best_practice",
                "LESSON_LEARNED": "lesson_learned",
            },
        ),
        "synthesis_source": EnumDef(
            "SynthesisSource",
            {
                "INCIDENT_REVIEW": "incident_review",
                "RUNBOOK_EXECUTION": "runbook_execution",
                "EXPERT_INPUT": "expert_input",
                "ML_EXTRACTION": "ml_extraction",
                "DOCUMENTATION": "documentation",
            },
        ),
        "knowledge_maturity": EnumDef(
            "KnowledgeMaturity",
            {
                "VALIDATED": "validated",
                "REVIEWED": "reviewed",
                "DRAFT": "draft",
                "CANDIDATE": "candidate",
                "DEPRECATED": "deprecated",
            },
        ),
    },
)

# Backward-compatible re-exports
KnowledgeType = OperationalKnowledgeSynthesizer.KnowledgeType
SynthesisSource = OperationalKnowledgeSynthesizer.SynthesisSource
KnowledgeMaturity = OperationalKnowledgeSynthesizer.KnowledgeMaturity
KnowledgeRecord = OperationalKnowledgeSynthesizer.Record
KnowledgeAnalysis = OperationalKnowledgeSynthesizer.Analysis
OperationalKnowledgeReport = OperationalKnowledgeSynthesizer.Report
