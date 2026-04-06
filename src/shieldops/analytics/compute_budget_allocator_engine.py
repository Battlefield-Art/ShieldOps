"""Compute Budget Allocator Engine — allocate experiment budgets, detect waste, and forecast b..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ComputeBudgetAllocatorEngine = engine(
    "ComputeBudgetAllocatorEngine",
    description="Allocate experiment budgets, detect waste, and forecast budget exhaustion.",
    enums={
        "unit": EnumDef(
            "BudgetUnit",
            {
                "GPU_HOURS": "gpu_hours",
                "CPU_HOURS": "cpu_hours",
                "MEMORY_GB_HOURS": "memory_gb_hours",
                "API_CALLS": "api_calls",
            },
        ),
        "strategy": EnumDef(
            "AllocationStrategy",
            {
                "EQUAL_SPLIT": "equal_split",
                "PROPORTIONAL": "proportional",
                "PRIORITY_WEIGHTED": "priority_weighted",
                "ADAPTIVE": "adaptive",
            },
        ),
        "status": EnumDef(
            "BudgetStatus",
            {
                "UNDER_BUDGET": "under_budget",
                "NEAR_LIMIT": "near_limit",
                "AT_LIMIT": "at_limit",
                "EXCEEDED": "exceeded",
            },
        ),
    },
    record_fields=[
        FieldDef("allocated", float, 0.0),
        FieldDef("consumed", float, 0.0),
        FieldDef("priority", float, 1.0),
        FieldDef("description", str, ""),
    ],
    key_field="experiment_id",
)

# Backward-compatible re-exports
BudgetUnit = ComputeBudgetAllocatorEngine.BudgetUnit
AllocationStrategy = ComputeBudgetAllocatorEngine.AllocationStrategy
BudgetStatus = ComputeBudgetAllocatorEngine.BudgetStatus
ComputeBudgetRecord = ComputeBudgetAllocatorEngine.Record
ComputeBudgetAnalysis = ComputeBudgetAllocatorEngine.Analysis
ComputeBudgetReport = ComputeBudgetAllocatorEngine.Report
