"""Tool functions for Purple Team Orchestrator Agent."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.purple_team_orchestrator.models import (
    AttackExecution,
    DetectionMonitor,
    ExercisePlan,
    ExerciseScore,
    ExerciseType,
    ResponseAssessment,
    TeamScore,
)

logger = structlog.get_logger()


class PurpleTeamOrchestratorToolkit:
    """Tools for purple team exercise orchestration."""

    def __init__(
        self,
        red_team_client: Any | None = None,
        blue_team_client: Any | None = None,
        siem_client: Any | None = None,
    ) -> None:
        self._red_team = red_team_client
        self._blue_team = blue_team_client
        self._siem = siem_client

    async def create_plan(
        self,
        exercise_type: ExerciseType,
        tenant_id: str,
    ) -> ExercisePlan:
        """Create an exercise plan."""
        logger.info(
            "purple_team.creating_plan",
            exercise_type=exercise_type,
            tenant_id=tenant_id,
        )

        return ExercisePlan(
            id=f"ex-{uuid4().hex[:8]}",
            name=f"Purple Team {exercise_type.value}",
            exercise_type=exercise_type,
            objectives=[
                "Test detection coverage",
                "Measure response times",
                "Validate containment procedures",
            ],
            attack_scenarios=[
                "T1566.001 — Spearphishing",
                "T1059.001 — PowerShell execution",
                "T1053.005 — Scheduled task",
                "T1021.002 — SMB lateral movement",
            ],
            expected_detections=[
                "Email gateway alert",
                "EDR process alert",
                "Sysmon task creation",
                "Network anomaly alert",
            ],
            duration_minutes=90,
            participants=[
                "red-team-lead",
                "blue-team-lead",
                "soc-analyst-1",
            ],
        )

    async def execute_attacks(
        self,
        plan: ExercisePlan,
    ) -> list[AttackExecution]:
        """Execute planned attack scenarios."""
        logger.info(
            "purple_team.executing_attacks",
            plan_id=plan.id,
            scenario_count=len(plan.attack_scenarios),
        )

        now = time.time()
        attacks = []
        for i, scenario in enumerate(plan.attack_scenarios):
            technique = scenario.split(" — ")[0].strip()
            attacks.append(
                AttackExecution(
                    id=f"atk-{uuid4().hex[:8]}",
                    scenario=scenario,
                    technique_id=technique,
                    target=f"target-{i + 1}",
                    success=i % 3 != 0,
                    timestamp=now + i * 60,
                    evidence=[
                        f"Executed {technique} safely",
                        "Logged to attack journal",
                    ],
                )
            )
        return attacks

    async def monitor_detections(
        self,
        attacks: list[AttackExecution],
    ) -> list[DetectionMonitor]:
        """Monitor blue team detections."""
        logger.info(
            "purple_team.monitoring_detections",
            attack_count=len(attacks),
        )

        detections = []
        for i, attack in enumerate(attacks):
            detected = i % 4 != 3
            detections.append(
                DetectionMonitor(
                    id=f"det-{uuid4().hex[:8]}",
                    attack_id=attack.id,
                    detection_rule=(f"rule-{attack.technique_id}"),
                    detected=detected,
                    time_to_detect_sec=(15.0 + i * 5 if detected else 0.0),
                    alert_fidelity=(0.85 if detected else 0.0),
                    false_positive=False,
                )
            )
        return detections

    async def assess_responses(
        self,
        detections: list[DetectionMonitor],
    ) -> list[ResponseAssessment]:
        """Assess blue team responses."""
        logger.info(
            "purple_team.assessing_responses",
            detection_count=len(detections),
        )

        assessments = []
        for det in detections:
            if not det.detected:
                continue
            assessments.append(
                ResponseAssessment(
                    id=f"resp-{uuid4().hex[:8]}",
                    detection_id=det.id,
                    response_action="isolate_endpoint",
                    time_to_respond_sec=(det.time_to_detect_sec + 30),
                    containment_effective=True,
                    evidence=[
                        "Endpoint isolated",
                        "Incident ticket created",
                    ],
                )
            )
        return assessments

    async def score_exercise(
        self,
        attacks: list[AttackExecution],
        detections: list[DetectionMonitor],
        responses: list[ResponseAssessment],
    ) -> list[ExerciseScore]:
        """Score the overall exercise."""
        logger.info(
            "purple_team.scoring_exercise",
            attacks=len(attacks),
            detections=len(detections),
        )

        total_attacks = len(attacks)
        detected = sum(1 for d in detections if d.detected)
        responded = len(responses)
        contained = sum(1 for r in responses if r.containment_effective)

        det_pct = detected / total_attacks * 100 if total_attacks else 0
        resp_pct = responded / detected * 100 if detected else 0
        cont_pct = contained / responded * 100 if responded else 0

        def _grade(pct: float) -> TeamScore:
            if pct >= 90:
                return TeamScore.EXCELLENT
            if pct >= 75:
                return TeamScore.GOOD
            if pct >= 60:
                return TeamScore.ADEQUATE
            if pct >= 40:
                return TeamScore.NEEDS_IMPROVEMENT
            return TeamScore.FAILED

        return [
            ExerciseScore(
                id=f"score-{uuid4().hex[:8]}",
                category="detection",
                score=_grade(det_pct),
                points=det_pct,
                details=(f"{detected}/{total_attacks} attacks detected"),
            ),
            ExerciseScore(
                id=f"score-{uuid4().hex[:8]}",
                category="response",
                score=_grade(resp_pct),
                points=resp_pct,
                details=(f"{responded}/{detected} detections responded to"),
            ),
            ExerciseScore(
                id=f"score-{uuid4().hex[:8]}",
                category="containment",
                score=_grade(cont_pct),
                points=cont_pct,
                details=(f"{contained}/{responded} responses contained"),
            ),
        ]
