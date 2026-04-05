"""Alert Narrative Composer Engine — track and analyze alert-to-narrative composition quality."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AlertNarrativeComposerEngine = engine(
    "AlertNarrativeComposerEngine",
    description="Track and analyze alert-to-narrative composition quality.",
    enums={
        "narrative_type": EnumDef(
            "NarrativeType",
            {
                "SINGLE_ALERT": "single_alert",
                "CORRELATED": "correlated",
                "KILL_CHAIN": "kill_chain",
                "CAMPAIGN": "campaign",
                "INSIDER_THREAT": "insider_threat",
            },
        ),
        "composition_quality": EnumDef(
            "CompositionQuality",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "MODERATE": "moderate",
                "POOR": "poor",
                "INCOMPLETE": "incomplete",
            },
        ),
        "alert_source": EnumDef(
            "AlertSource",
            {
                "EDR": "edr",
                "SIEM": "siem",
                "CLOUD": "cloud",
                "IDENTITY": "identity",
                "NETWORK": "network",
            },
        ),
    },
    record_fields=[
        FieldDef("alert_count", int, 0),
        FieldDef("vendor_count", int, 0),
        FieldDef("correlation_confidence", float, 0.0),
        FieldDef("time_span_minutes", float, 0.0),
    ],
    key_field="situation_id",
)

# Backward-compatible re-exports
NarrativeType = AlertNarrativeComposerEngine.NarrativeType
CompositionQuality = AlertNarrativeComposerEngine.CompositionQuality
AlertSource = AlertNarrativeComposerEngine.AlertSource
NarrativeRecord = AlertNarrativeComposerEngine.Record
NarrativeAnalysis = AlertNarrativeComposerEngine.Analysis
NarrativeReport = AlertNarrativeComposerEngine.Report
