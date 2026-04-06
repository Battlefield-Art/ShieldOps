"""Reservation Yield Optimizer analyze reservation coverage, recommend exchanges, forecast res..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ReservationYieldOptimizer = engine(
    "ReservationYieldOptimizer",
    description="Analyze reservation coverage, recommend exchanges, forecast expiry impact.",
    enums={
        "reservation_type": EnumDef(
            "ReservationType",
            {
                "RESERVED_INSTANCE": "reserved_instance",
                "SAVINGS_PLAN": "savings_plan",
                "COMMITTED_USE": "committed_use",
                "SPOT": "spot",
            },
        ),
        "coverage_status": EnumDef(
            "CoverageStatus",
            {
                "FULLY_COVERED": "fully_covered",
                "PARTIAL": "partial",
                "UNCOVERED": "uncovered",
                "OVER_COMMITTED": "over_committed",
            },
        ),
        "yield_level": EnumDef(
            "YieldLevel",
            {
                "OPTIMAL": "optimal",
                "GOOD": "good",
                "SUBOPTIMAL": "suboptimal",
                "WASTEFUL": "wasteful",
            },
        ),
    },
    record_fields=[
        FieldDef("monthly_cost", float, 0.0),
        FieldDef("utilization_pct", float, 0.0),
        FieldDef("expiry_days", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="reservation_id",
)

# Backward-compatible re-exports
ReservationType = ReservationYieldOptimizer.ReservationType
CoverageStatus = ReservationYieldOptimizer.CoverageStatus
YieldLevel = ReservationYieldOptimizer.YieldLevel
ReservationYieldRecord = ReservationYieldOptimizer.Record
ReservationYieldAnalysis = ReservationYieldOptimizer.Analysis
ReservationYieldReport = ReservationYieldOptimizer.Report
