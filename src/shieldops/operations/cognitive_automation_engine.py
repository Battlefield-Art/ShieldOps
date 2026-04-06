"""Cognitive Automation Engine — cognitive automation with decision-making capabilities."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

CognitiveAutomationEngine = engine(
    "CognitiveAutomationEngine",
    description="Cognitive Automation Engine — cognitive automation with decision-making cap...",
    enums={
        "decision_type": EnumDef(
            "DecisionType",
            {
                "TRIAGE": "triage",
                "ESCALATION": "escalation",
                "REMEDIATION": "remediation",
                "OPTIMIZATION": "optimization",
                "PREDICTION": "prediction",
            },
        ),
        "cognitive_source": EnumDef(
            "CognitiveSource",
            {
                "ML_MODEL": "ml_model",
                "RULE_ENGINE": "rule_engine",
                "EXPERT_SYSTEM": "expert_system",
                "LLM": "llm",
                "HYBRID": "hybrid",
            },
        ),
        "decision_confidence": EnumDef(
            "DecisionConfidence",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNCERTAIN": "uncertain",
                "OVERRIDE": "override",
            },
        ),
    },
)

# Backward-compatible re-exports
DecisionType = CognitiveAutomationEngine.DecisionType
CognitiveSource = CognitiveAutomationEngine.CognitiveSource
DecisionConfidence = CognitiveAutomationEngine.DecisionConfidence
CognitiveRecord = CognitiveAutomationEngine.Record
CognitiveAnalysis = CognitiveAutomationEngine.Analysis
CognitiveAutomationReport = CognitiveAutomationEngine.Report
