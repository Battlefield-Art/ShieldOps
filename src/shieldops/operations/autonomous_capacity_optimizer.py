"""Autonomous Capacity Optimizer — autonomous capacity optimization and scaling."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutonomousCapacityOptimizer = engine(
    "AutonomousCapacityOptimizer",
    module="operations",  # uses record_item
    description="Autonomous Capacity Optimizer for capacity optimization and scaling decisions.",
    enums={
        "scaling_direction": EnumDef(
            "ScalingDirection",
            {
                "UP": "up",
                "DOWN": "down",
                "HORIZONTAL": "horizontal",
                "VERTICAL": "vertical",
            },
        ),
        "capacity_signal": EnumDef(
            "CapacitySignal",
            {
                "CPU": "cpu",
                "MEMORY": "memory",
                "NETWORK": "network",
                "STORAGE": "storage",
            },
        ),
        "optimization_mode": EnumDef(
            "OptimizationMode",
            {
                "CONSERVATIVE": "conservative",
                "BALANCED": "balanced",
                "AGGRESSIVE": "aggressive",
                "CUSTOM": "custom",
            },
        ),
    },
)

# Backward-compatible re-exports
ScalingDirection = AutonomousCapacityOptimizer.ScalingDirection
CapacitySignal = AutonomousCapacityOptimizer.CapacitySignal
OptimizationMode = AutonomousCapacityOptimizer.OptimizationMode
CapacityRecord = AutonomousCapacityOptimizer.Record
CapacityAnalysis = AutonomousCapacityOptimizer.Analysis
AutonomousCapacityReport = AutonomousCapacityOptimizer.Report
