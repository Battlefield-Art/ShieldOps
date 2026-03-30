"""Tool functions for the On-Call Optimizer."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from .models import BurnoutRisk, ShiftType

logger = structlog.get_logger()


class OnCallOptimizerToolkit:
    """Toolkit for on-call optimization workflows."""

    def __init__(
        self,
        schedule_service: Any | None = None,
        incident_service: Any | None = None,
    ) -> None:
        self._schedules = schedule_service
        self._incidents = incident_service

    async def analyze_schedules(
        self,
        team_id: str,
        team_members: list[str],
        lookback_days: int,
    ) -> dict[str, Any]:
        """Analyze on-call schedule patterns."""
        if not team_members:
            team_members = [
                "alice",
                "bob",
                "charlie",
                "diana",
            ]

        member_shifts: dict[str, dict[str, int]] = {}
        for i, member in enumerate(team_members):
            primary = 8 + (i * 2)
            weekend = 3 + i
            holiday = 1 + (i % 2)
            member_shifts[member] = {
                ShiftType.PRIMARY.value: primary,
                ShiftType.SECONDARY.value: primary - 2,
                ShiftType.WEEKEND.value: weekend,
                ShiftType.HOLIDAY.value: holiday,
                "total_hours": primary * 12 + weekend * 24,
            }

        total_shifts = sum(s.get(ShiftType.PRIMARY.value, 0) for s in member_shifts.values())

        logger.info(
            "oco.analyze_schedules",
            members=len(team_members),
            total_shifts=total_shifts,
        )
        return {
            "id": f"oco-sch-{uuid4().hex[:8]}",
            "team_id": team_id,
            "member_count": len(team_members),
            "lookback_days": lookback_days,
            "member_shifts": member_shifts,
            "total_shifts": total_shifts,
            "shift_types_used": [s.value for s in ShiftType if s != ShiftType.FOLLOW_THE_SUN],
        }

    async def evaluate_load(
        self,
        schedule_analysis: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate load distribution fairness."""
        shifts = schedule_analysis.get(
            "member_shifts",
            {},
        )
        hours = [v.get("total_hours", 0) for v in shifts.values()]
        if not hours:
            hours = [0]

        avg_hours = sum(hours) / len(hours)
        max_hours = max(hours)
        min_hours = min(hours)
        spread = max_hours - min_hours

        if spread < avg_hours * 0.1:
            fairness = "excellent"
        elif spread < avg_hours * 0.25:
            fairness = "good"
        elif spread < avg_hours * 0.5:
            fairness = "fair"
        else:
            fairness = "poor"

        logger.info(
            "oco.evaluate_load",
            fairness=fairness,
            spread=spread,
        )
        return {
            "id": f"oco-load-{uuid4().hex[:8]}",
            "avg_hours": round(avg_hours, 1),
            "max_hours": max_hours,
            "min_hours": min_hours,
            "spread_hours": spread,
            "fairness": fairness,
            "incidents_per_shift": 2.3,
            "pages_after_hours_pct": 35.0,
        }

    async def detect_burnout(
        self,
        schedule_analysis: dict[str, Any],
        load_evaluation: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Detect burnout risk per team member."""
        shifts = schedule_analysis.get(
            "member_shifts",
            {},
        )
        avg = load_evaluation.get("avg_hours", 100)
        assessments: list[dict[str, Any]] = []

        for member, data in shifts.items():
            hours = data.get("total_hours", 0)
            ratio = hours / avg if avg > 0 else 1.0

            if ratio > 1.5:
                risk = BurnoutRisk.CRITICAL
            elif ratio > 1.3:
                risk = BurnoutRisk.HIGH
            elif ratio > 1.1:
                risk = BurnoutRisk.MODERATE
            elif ratio > 0.9:
                risk = BurnoutRisk.LOW
            else:
                risk = BurnoutRisk.HEALTHY

            assessments.append(
                {
                    "id": f"oco-brn-{uuid4().hex[:8]}",
                    "member": member,
                    "total_hours": hours,
                    "load_ratio": round(ratio, 2),
                    "burnout_risk": risk.value,
                    "consecutive_weekends": data.get(
                        ShiftType.WEEKEND.value,
                        0,
                    ),
                }
            )

        logger.info(
            "oco.detect_burnout",
            assessments=len(assessments),
        )
        return assessments

    async def optimize_rotation(
        self,
        schedule_analysis: dict[str, Any],
        burnout_assessments: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate optimized rotation schedule."""
        members = list(
            schedule_analysis.get(
                "member_shifts",
                {},
            ).keys(),
        )
        at_risk = [
            a.get("member")
            for a in burnout_assessments
            if a.get("burnout_risk")
            in (
                "critical",
                "high",
            )
        ]

        proposed: dict[str, dict[str, int]] = {}
        target = schedule_analysis.get(
            "total_shifts",
            20,
        ) // max(len(members), 1)

        for member in members:
            primary = target
            if member in at_risk:
                primary = max(target - 3, 2)
            proposed[member] = {
                ShiftType.PRIMARY.value: primary,
                ShiftType.WEEKEND.value: 2,
                ShiftType.HOLIDAY.value: 1,
            }

        logger.info(
            "oco.optimize_rotation",
            members=len(members),
        )
        return {
            "id": f"oco-opt-{uuid4().hex[:8]}",
            "proposed_rotation": proposed,
            "at_risk_relieved": at_risk,
            "target_shifts_per_member": target,
            "optimization_type": "fairness_balance",
        }

    async def recommend_changes(
        self,
        load_evaluation: dict[str, Any],
        burnout_assessments: list[dict[str, Any]],
        optimized_rotation: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Generate actionable recommendations."""
        recs: list[dict[str, Any]] = []
        at_risk = [
            a
            for a in burnout_assessments
            if a.get("burnout_risk")
            in (
                "critical",
                "high",
            )
        ]

        if at_risk:
            recs.append(
                {
                    "id": f"oco-rec-{uuid4().hex[:8]}",
                    "priority": "high",
                    "title": "Reduce load for at-risk members",
                    "detail": (f"{len(at_risk)} members at elevated burnout risk"),
                    "action": "rebalance",
                }
            )

        fairness = load_evaluation.get("fairness", "")
        if fairness in ("fair", "poor"):
            recs.append(
                {
                    "id": f"oco-rec-{uuid4().hex[:8]}",
                    "priority": "high",
                    "title": "Improve schedule fairness",
                    "detail": f"Current fairness: {fairness}",
                    "action": "redistribute",
                }
            )

        recs.append(
            {
                "id": f"oco-rec-{uuid4().hex[:8]}",
                "priority": "medium",
                "title": "Consider follow-the-sun model",
                "detail": "Reduce after-hours pages",
                "action": "evaluate",
            }
        )

        recs.append(
            {
                "id": f"oco-rec-{uuid4().hex[:8]}",
                "priority": "low",
                "title": "Automate common incident types",
                "detail": "Reduce page volume via automation",
                "action": "automate",
            }
        )

        logger.info(
            "oco.recommend_changes",
            count=len(recs),
        )
        return recs
