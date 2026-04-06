"""Cost Aware Scaling Optimizer cost-aware scaling optimization balancing performance and spend."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

CostAwareScalingOptimizer = engine(
    "CostAwareScalingOptimizer",
    description="Cost Aware Scaling Optimizer cost-aware scaling optimization balancing perf...",
    enums={
        "scaling_mode": EnumDef(
            "ScalingMode",
            {
                "PERFORMANCE_FIRST": "performance_first",
                "COST_FIRST": "cost_first",
                "BALANCED": "balanced",
                "PEAK_HANDLING": "peak_handling",
                "MINIMUM": "minimum",
            },
        ),
        "cost_signal": EnumDef(
            "CostSignal",
            {
                "SPOT_PRICE": "spot_price",
                "RI_UTILIZATION": "ri_utilization",
                "ON_DEMAND_SPEND": "on_demand_spend",
                "SAVINGS_PLAN": "savings_plan",
                "BUDGET_REMAINING": "budget_remaining",
            },
        ),
        "optimization_result": EnumDef(
            "OptimizationResult",
            {
                "SAVINGS_ACHIEVED": "savings_achieved",
                "PERFORMANCE_MAINTAINED": "performance_maintained",
                "TRADE_OFF": "trade_off",
                "NO_CHANGE": "no_change",
                "REVERTED": "reverted",
            },
        ),
    },
)

# Backward-compatible re-exports
ScalingMode = CostAwareScalingOptimizer.ScalingMode
CostSignal = CostAwareScalingOptimizer.CostSignal
OptimizationResult = CostAwareScalingOptimizer.OptimizationResult
CostScalingRecord = CostAwareScalingOptimizer.Record
CostScalingAnalysis = CostAwareScalingOptimizer.Analysis
CostAwareScalingReport = CostAwareScalingOptimizer.Report
