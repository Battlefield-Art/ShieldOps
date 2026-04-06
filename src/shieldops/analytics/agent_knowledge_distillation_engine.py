"""Agent Knowledge Distillation Engine — distill expert agent knowledge into smaller agents."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentKnowledgeDistillationEngine = engine(
    "AgentKnowledgeDistillationEngine",
    description="Track and optimize knowledge distillation from expert to student agents.",
    enums={
        "distillation_method": EnumDef(
            "DistillationMethod",
            {
                "RESPONSE_MATCHING": "response_matching",
                "FEATURE_TRANSFER": "feature_transfer",
                "BEHAVIOR_CLONING": "behavior_cloning",
                "ENSEMBLE_AVERAGING": "ensemble_averaging",
            },
        ),
        "knowledge_type": EnumDef(
            "KnowledgeType",
            {
                "INVESTIGATION_PATTERNS": "investigation_patterns",
                "REMEDIATION_STRATEGIES": "remediation_strategies",
                "THREAT_SIGNATURES": "threat_signatures",
                "ROUTING_RULES": "routing_rules",
            },
        ),
        "transfer_outcome": EnumDef(
            "TransferOutcome",
            {
                "SUCCESSFUL": "successful",
                "PARTIAL": "partial",
                "FAILED": "failed",
                "REGRESSED": "regressed",
            },
        ),
    },
    record_fields=[
        FieldDef("expert_agent", str, ""),
        FieldDef("student_agent", str, ""),
    ],
)

# Backward-compatible re-exports
DistillationMethod = AgentKnowledgeDistillationEngine.DistillationMethod
KnowledgeType = AgentKnowledgeDistillationEngine.KnowledgeType
TransferOutcome = AgentKnowledgeDistillationEngine.TransferOutcome
DistillationRecord = AgentKnowledgeDistillationEngine.Record
DistillationAnalysis = AgentKnowledgeDistillationEngine.Analysis
DistillationReport = AgentKnowledgeDistillationEngine.Report
