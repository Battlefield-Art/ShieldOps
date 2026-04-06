"""Bridge Entity Discovery Engine — find linking entities across disparate alerts/signals, sco..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

BridgeEntityDiscoveryEngine = engine(
    "BridgeEntityDiscoveryEngine",
    description="Find linking entities across disparate alerts/signals, score bridge signifi...",
    enums={
        "entity_type": EnumDef(
            "EntityType",
            {
                "SERVICE": "service",
                "HOST": "host",
                "DEPLOYMENT": "deployment",
                "CONFIGURATION": "configuration",
            },
        ),
        "bridge_strength": EnumDef(
            "BridgeStrength",
            {
                "STRONG": "strong",
                "MODERATE": "moderate",
                "WEAK": "weak",
                "SPECULATIVE": "speculative",
            },
        ),
        "discovery_method": EnumDef(
            "DiscoveryMethod",
            {
                "CORRELATION": "correlation",
                "TOPOLOGY": "topology",
                "TEMPORAL": "temporal",
                "SEMANTIC": "semantic",
            },
        ),
    },
    record_fields=[
        FieldDef("connected_alerts", int, 0),
        FieldDef("source_signal", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="significance_score",
    key_field="entity_id",
)

# Backward-compatible re-exports
EntityType = BridgeEntityDiscoveryEngine.EntityType
BridgeStrength = BridgeEntityDiscoveryEngine.BridgeStrength
DiscoveryMethod = BridgeEntityDiscoveryEngine.DiscoveryMethod
BridgeEntityRecord = BridgeEntityDiscoveryEngine.Record
BridgeEntityAnalysis = BridgeEntityDiscoveryEngine.Analysis
BridgeEntityReport = BridgeEntityDiscoveryEngine.Report
