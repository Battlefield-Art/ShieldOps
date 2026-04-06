"""Alert Intelligence Engine — intelligent alert management with context and correlation."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AlertIntelligenceEngine = engine(
    "AlertIntelligenceEngine",
    description="Alert Intelligence Engine — intelligent alert management with context and c...",
    enums={
        "alert_intel_type": EnumDef(
            "AlertIntelType",
            {
                "CORRELATION": "correlation",
                "SUPPRESSION": "suppression",
                "ENRICHMENT": "enrichment",
                "ROUTING": "routing",
                "PREDICTION": "prediction",
            },
        ),
        "alert_source": EnumDef(
            "AlertSource",
            {
                "PROMETHEUS": "prometheus",
                "PAGERDUTY": "pagerduty",
                "OPSGENIE": "opsgenie",
                "DATADOG": "datadog",
                "CUSTOM": "custom",
            },
        ),
        "intelligence_level": EnumDef(
            "IntelligenceLevel",
            {
                "AUTOMATED": "automated",
                "ASSISTED": "assisted",
                "MANUAL": "manual",
                "OVERRIDE": "override",
                "LEARNING": "learning",
            },
        ),
    },
)

# Backward-compatible re-exports
AlertIntelType = AlertIntelligenceEngine.AlertIntelType
AlertSource = AlertIntelligenceEngine.AlertSource
IntelligenceLevel = AlertIntelligenceEngine.IntelligenceLevel
AlertIntelRecord = AlertIntelligenceEngine.Record
AlertIntelAnalysis = AlertIntelligenceEngine.Analysis
AlertIntelligenceReport = AlertIntelligenceEngine.Report
