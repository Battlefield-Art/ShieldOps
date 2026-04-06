"""RemediationKnowledgeGraph — build and query a knowledge graph of remediation patterns."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

RemediationKnowledgeGraph = engine(
    "RemediationKnowledgeGraph",
    description="Build and query a knowledge graph of remediation patterns.",
    enums={
        "record_type": EnumDef(
            "RemediationType",
            {
                "RESTART": "restart",
                "SCALE": "scale",
                "PATCH": "patch",
                "ROLLBACK": "rollback",
                "CONFIG_CHANGE": "config_change",
            },
        ),
        "source": EnumDef(
            "RemediationSource",
            {
                "MONITORING": "monitoring",
                "ALERT": "alert",
                "SCHEDULE": "schedule",
                "MANUAL": "manual",
                "AUTO_DETECT": "auto_detect",
            },
        ),
        "level": EnumDef(
            "RemediationLevel",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "ROUTINE": "routine",
            },
        ),
    },
)

# Backward-compatible re-exports
RemediationType = RemediationKnowledgeGraph.RemediationType
RemediationSource = RemediationKnowledgeGraph.RemediationSource
RemediationLevel = RemediationKnowledgeGraph.RemediationLevel
RemediationRecord = RemediationKnowledgeGraph.Record
RemediationAnalysis = RemediationKnowledgeGraph.Analysis
RemediationReport = RemediationKnowledgeGraph.Report
