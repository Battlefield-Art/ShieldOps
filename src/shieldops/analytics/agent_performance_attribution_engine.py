"""Agent Performance Attribution Engine — compute component attribution, detect performance bo..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentPerformanceAttributionEngine = engine(
    "AgentPerformanceAttributionEngine",
    description="Attribute performance to specific agent components, detect bottlenecks, and...",
    enums={
        "component_type": EnumDef(
            "ComponentType",
            {
                "PERCEPTION": "perception",
                "REASONING": "reasoning",
                "ACTION": "action",
                "COMMUNICATION": "communication",
            },
        ),
        "attribution_method": EnumDef(
            "AttributionMethod",
            {
                "SHAPLEY": "shapley",
                "ABLATION": "ablation",
                "GRADIENT": "gradient",
                "PERTURBATION": "perturbation",
            },
        ),
        "performance_impact": EnumDef(
            "PerformanceImpact",
            {
                "CRITICAL": "critical",
                "SIGNIFICANT": "significant",
                "MODERATE": "moderate",
                "NEGLIGIBLE": "negligible",
            },
        ),
    },
    record_fields=[
        FieldDef("baseline_performance", float, 0.0),
        FieldDef("measured_performance", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="attribution_score",
    key_field="agent_id",
)

# Backward-compatible re-exports
ComponentType = AgentPerformanceAttributionEngine.ComponentType
AttributionMethod = AgentPerformanceAttributionEngine.AttributionMethod
PerformanceImpact = AgentPerformanceAttributionEngine.PerformanceImpact
PerformanceAttributionRecord = AgentPerformanceAttributionEngine.Record
PerformanceAttributionAnalysis = AgentPerformanceAttributionEngine.Analysis
PerformanceAttributionReport = AgentPerformanceAttributionEngine.Report
