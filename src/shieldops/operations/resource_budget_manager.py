"""Resource Budget Manager Track and manage experiment resource budgets with allocation strate..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ResourceBudgetManager = engine(
    "ResourceBudgetManager",
    module="operations",  # uses record_item
    description="Track and manage experiment resource budgets with allocation and exhaustion...",
    enums={
        "resource_type": EnumDef(
            "ResourceType",
            {
                "GPU": "gpu",
                "CPU": "cpu",
                "MEMORY": "memory",
                "STORAGE": "storage",
            },
        ),
        "strategy": EnumDef(
            "AllocationStrategy",
            {
                "FIXED": "fixed",
                "ELASTIC": "elastic",
                "PRIORITY": "priority",
                "FAIR_SHARE": "fair_share",
            },
        ),
        "status": EnumDef(
            "BudgetStatus",
            {
                "UNDER_BUDGET": "under_budget",
                "AT_LIMIT": "at_limit",
                "OVER_BUDGET": "over_budget",
                "EXHAUSTED": "exhausted",
            },
        ),
    },
    record_fields=[
        FieldDef("allocated", float, 0.0),
        FieldDef("consumed", float, 0.0),
    ],
)

# Backward-compatible re-exports
ResourceType = ResourceBudgetManager.ResourceType
AllocationStrategy = ResourceBudgetManager.AllocationStrategy
BudgetStatus = ResourceBudgetManager.BudgetStatus
BudgetRecord = ResourceBudgetManager.Record
BudgetAnalysis = ResourceBudgetManager.Analysis
BudgetReport = ResourceBudgetManager.Report
