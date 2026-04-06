"""Incident Cost Attribution Engine — compute cost breakdown, detect high-cost patterns, rank..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IncidentCostAttributionEngine = engine(
    "IncidentCostAttributionEngine",
    description="Compute incident cost breakdown, detect high-cost patterns, rank incidents...",
    enums={
        "cost_category": EnumDef(
            "CostCategory",
            {
                "ENGINEERING_TIME": "engineering_time",
                "REVENUE_LOSS": "revenue_loss",
                "SLA_PENALTY": "sla_penalty",
                "INFRASTRUCTURE": "infrastructure",
            },
        ),
        "cost_period": EnumDef(
            "CostPeriod",
            {
                "HOURLY": "hourly",
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
            },
        ),
        "cost_severity": EnumDef(
            "CostSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("cost_amount", float, 0.0),
        FieldDef("currency", str, "USD"),
        FieldDef("description", str, ""),
    ],
    key_field="incident_id",
)

# Backward-compatible re-exports
CostCategory = IncidentCostAttributionEngine.CostCategory
CostPeriod = IncidentCostAttributionEngine.CostPeriod
CostSeverity = IncidentCostAttributionEngine.CostSeverity
IncidentCostRecord = IncidentCostAttributionEngine.Record
IncidentCostAnalysis = IncidentCostAttributionEngine.Analysis
IncidentCostReport = IncidentCostAttributionEngine.Report
