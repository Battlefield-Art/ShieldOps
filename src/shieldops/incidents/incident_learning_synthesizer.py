"""Incident Learning Synthesizer — learning extraction and synthesis from incidents."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

IncidentLearningSynthesizer = engine(
    "IncidentLearningSynthesizer",
    description="Incident Learning Synthesizer for learning extraction and synthesis.",
    enums={
        "learning_type": EnumDef(
            "LearningType",
            {
                "PATTERN": "pattern",
                "ANTIPATTERN": "antipattern",
                "BEST_PRACTICE": "best_practice",
                "FAILURE_MODE": "failure_mode",
            },
        ),
        "knowledge_source": EnumDef(
            "KnowledgeSource",
            {
                "POSTMORTEM": "postmortem",
                "RUNBOOK": "runbook",
                "ALERT_HISTORY": "alert_history",
                "CHANGE_LOG": "change_log",
            },
        ),
        "applicability_scope": EnumDef(
            "ApplicabilityScope",
            {
                "SERVICE": "service",
                "TEAM": "team",
                "ORGANIZATION": "organization",
                "INDUSTRY": "industry",
            },
        ),
    },
)

# Backward-compatible re-exports
LearningType = IncidentLearningSynthesizer.LearningType
KnowledgeSource = IncidentLearningSynthesizer.KnowledgeSource
ApplicabilityScope = IncidentLearningSynthesizer.ApplicabilityScope
LearningRecord = IncidentLearningSynthesizer.Record
LearningAnalysis = IncidentLearningSynthesizer.Analysis
IncidentLearningReport = IncidentLearningSynthesizer.Report
