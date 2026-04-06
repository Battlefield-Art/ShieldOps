"""AgentResourceGovernorEngine — Enforce resource limits across agent fleet."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentResourceGovernorEngine = engine(
    "AgentResourceGovernorEngine",
    description="Enforce resource limits across agent fleet (LLM tokens, compute, API calls).",
    enums={
        "resource_policy": EnumDef(
            "ResourcePolicy",
            {
                "ENFORCE": "enforce",
                "WARN": "warn",
                "MONITOR": "monitor",
            },
        ),
        "limit_scope": EnumDef(
            "LimitScope",
            {
                "PER_AGENT": "per_agent",
                "PER_TENANT": "per_tenant",
                "GLOBAL": "global",
            },
        ),
        "budget_period": EnumDef(
            "BudgetPeriod",
            {
                "HOURLY": "hourly",
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
            },
        ),
    },
    record_fields=[
        FieldDef("usage_amount", float, 0.0),
        FieldDef("budget_limit", float, 0.0),
    ],
)

# Backward-compatible re-exports
ResourcePolicy = AgentResourceGovernorEngine.ResourcePolicy
LimitScope = AgentResourceGovernorEngine.LimitScope
BudgetPeriod = AgentResourceGovernorEngine.BudgetPeriod
AgentResourceGovernorRecord = AgentResourceGovernorEngine.Record
AgentResourceGovernorAnalysis = AgentResourceGovernorEngine.Analysis
AgentResourceGovernorReport = AgentResourceGovernorEngine.Report
