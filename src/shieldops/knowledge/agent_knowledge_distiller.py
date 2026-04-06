"""Agent Knowledge Distiller Distill, compress, and prioritize agent learnings for efficient k..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentKnowledgeDistiller = engine(
    "AgentKnowledgeDistiller",
    description="Distill and prioritize agent learnings for efficient knowledge retention an...",
    enums={
        "knowledge_type": EnumDef(
            "KnowledgeType",
            {
                "PROCEDURAL": "procedural",
                "DECLARATIVE": "declarative",
                "HEURISTIC": "heuristic",
                "CONTEXTUAL": "contextual",
            },
        ),
        "method": EnumDef(
            "DistillationMethod",
            {
                "SUMMARIZATION": "summarization",
                "COMPRESSION": "compression",
                "EXTRACTION": "extraction",
                "SYNTHESIS": "synthesis",
            },
        ),
        "priority": EnumDef(
            "RetentionPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("topic", str, ""),
    ],
    score_field="density_score",
    key_field="agent_id",
)

# Backward-compatible re-exports
KnowledgeType = AgentKnowledgeDistiller.KnowledgeType
DistillationMethod = AgentKnowledgeDistiller.DistillationMethod
RetentionPriority = AgentKnowledgeDistiller.RetentionPriority
KnowledgeRecord = AgentKnowledgeDistiller.Record
KnowledgeAnalysis = AgentKnowledgeDistiller.Analysis
KnowledgeReport = AgentKnowledgeDistiller.Report
