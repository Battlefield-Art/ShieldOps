"""Tool functions for the Incident Simulator Agent."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_simulator.models import (
    ExerciseDesign,
    ExerciseScope,
    PerformanceMeasurement,
    PerformanceMetric,
    ReadinessScore,
    ResponseObservation,
    ScenarioInjection,
)

logger = structlog.get_logger()

# Scenario templates
SCENARIO_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "ransomware": [
        {
            "title": "Ransomware detected on server",
            "description": ("CrowdStrike alert: ransomware encrypting files on prod-db-01"),
            "severity": "critical",
            "target_role": "incident_commander",
            "expected": "Immediate isolation",
        },
        {
            "title": "Ransom note received",
            "description": ("Attacker demands 50 BTC payment within 48 hours"),
            "severity": "critical",
            "target_role": "executive",
            "expected": ("Engage legal, refuse payment"),
        },
        {
            "title": "Backup integrity unknown",
            "description": ("Backup team reports last verified backup is 72 hours old"),
            "severity": "high",
            "target_role": "technical_lead",
            "expected": "Verify backup integrity",
        },
    ],
    "data_breach": [
        {
            "title": "Unauthorized data access detected",
            "description": ("SIEM alert: bulk data export from customer database"),
            "severity": "critical",
            "target_role": "incident_commander",
            "expected": "Contain access immediately",
        },
        {
            "title": "Media inquiry received",
            "description": ("Reporter asking about data leak on dark web forum"),
            "severity": "high",
            "target_role": "communications",
            "expected": ("Coordinate with legal before any statement"),
        },
    ],
    "default": [
        {
            "title": "Service degradation detected",
            "description": ("Monitoring shows 50% increase in error rates"),
            "severity": "high",
            "target_role": "technical_lead",
            "expected": "Investigate root cause",
        },
    ],
}


class IncidentSimulatorToolkit:
    """Toolkit for incident simulation exercises."""

    def __init__(
        self,
        exercise_db: Any | None = None,
    ) -> None:
        self._exercise_db = exercise_db

    async def design_exercise(
        self,
        scenario: dict[str, Any],
    ) -> ExerciseDesign:
        """Design a simulation exercise."""
        scope_val = scenario.get("scope", "tabletop")
        scope = ExerciseScope(scope_val)

        scenario_type = scenario.get("type", "default")
        templates = SCENARIO_TEMPLATES.get(
            scenario_type,
            SCENARIO_TEMPLATES["default"],
        )

        objectives = scenario.get(
            "objectives",
            [
                "Test incident detection capabilities",
                "Evaluate team coordination",
                "Assess communication effectiveness",
            ],
        )

        participants = scenario.get(
            "participants",
            [
                "incident_commander",
                "technical_lead",
                "communications",
            ],
        )

        duration = {
            ExerciseScope.TABLETOP: 60,
            ExerciseScope.FUNCTIONAL: 120,
            ExerciseScope.FULL_SCALE: 240,
        }.get(scope, 60)

        exercise = ExerciseDesign(
            id=f"ex-{uuid4().hex[:12]}",
            name=scenario.get(
                "name",
                f"{scenario_type}_exercise",
            ),
            scope=scope,
            scenario_type=scenario_type,
            objectives=objectives,
            participants=participants,
            duration_min=duration,
            injects_planned=len(templates),
            success_criteria={
                "detection": "< 5 minutes",
                "containment": "< 30 minutes",
                "communication": "< 15 minutes",
            },
        )

        logger.info(
            "simulator.exercise_designed",
            exercise_id=exercise.id,
            scope=scope.value,
            injects=len(templates),
        )

        return exercise

    async def create_injects(
        self,
        exercise: ExerciseDesign,
    ) -> list[ScenarioInjection]:
        """Create scenario injects for the exercise."""
        templates = SCENARIO_TEMPLATES.get(
            exercise.scenario_type,
            SCENARIO_TEMPLATES["default"],
        )
        now = time.time()

        injects: list[ScenarioInjection] = []
        for i, tmpl in enumerate(templates):
            injects.append(
                ScenarioInjection(
                    id=f"inj-{uuid4().hex[:12]}",
                    inject_number=i + 1,
                    title=tmpl["title"],
                    description=tmpl["description"],
                    injected_at=now + (i * 300),
                    expected_response=tmpl["expected"],
                    severity=tmpl["severity"],
                    target_role=tmpl["target_role"],
                )
            )

        logger.info(
            "simulator.injects_created",
            exercise_id=exercise.id,
            count=len(injects),
        )

        return injects

    async def observe_responses(
        self,
        injects: list[ScenarioInjection],
    ) -> list[ResponseObservation]:
        """Observe and record team responses."""
        observations: list[ResponseObservation] = []

        for inject in injects:
            # Simulate observation
            response_time = 120.0 + (inject.inject_number * 30)
            quality = "good" if response_time < 180 else "adequate"

            observations.append(
                ResponseObservation(
                    id=f"obs-{uuid4().hex[:12]}",
                    inject_id=inject.id,
                    observer="simulation_engine",
                    response_time_sec=response_time,
                    actions_taken=[f"Responded to: {inject.title}"],
                    communication_quality=quality,
                    decision_quality=quality,
                    notes=(f"Response time: {response_time:.0f}s"),
                )
            )

        logger.info(
            "simulator.responses_observed",
            count=len(observations),
        )

        return observations

    async def measure_performance(
        self,
        observations: list[ResponseObservation],
    ) -> list[PerformanceMeasurement]:
        """Measure team performance metrics."""
        measurements: list[PerformanceMeasurement] = []

        if not observations:
            return measurements

        # Detection time
        avg_response = sum(o.response_time_sec for o in observations) / len(observations)
        measurements.append(
            PerformanceMeasurement(
                id=f"pm-{uuid4().hex[:12]}",
                metric=PerformanceMetric.DETECTION_TIME,
                value=avg_response,
                unit="seconds",
                target=120.0,
                met_target=avg_response <= 120.0,
            )
        )

        # Communication speed
        comm_scores = {
            "excellent": 4,
            "good": 3,
            "adequate": 2,
            "poor": 1,
        }
        avg_comm = sum(comm_scores.get(o.communication_quality, 2) for o in observations) / len(
            observations
        )
        measurements.append(
            PerformanceMeasurement(
                id=f"pm-{uuid4().hex[:12]}",
                metric=(PerformanceMetric.COMMUNICATION_SPEED),
                value=avg_comm,
                unit="score",
                target=3.0,
                met_target=avg_comm >= 3.0,
            )
        )

        # Decision quality
        dec_scores = {
            "excellent": 4,
            "good": 3,
            "adequate": 2,
            "poor": 1,
        }
        avg_dec = sum(dec_scores.get(o.decision_quality, 2) for o in observations) / len(
            observations
        )
        measurements.append(
            PerformanceMeasurement(
                id=f"pm-{uuid4().hex[:12]}",
                metric=(PerformanceMetric.DECISION_QUALITY),
                value=avg_dec,
                unit="score",
                target=3.0,
                met_target=avg_dec >= 3.0,
            )
        )

        logger.info(
            "simulator.performance_measured",
            metrics=len(measurements),
        )

        return measurements

    async def score_readiness(
        self,
        measurements: list[PerformanceMeasurement],
        observations: list[ResponseObservation],
    ) -> ReadinessScore:
        """Calculate overall readiness score."""
        if not measurements:
            return ReadinessScore(
                id=f"rs-{uuid4().hex[:12]}",
                overall_score=0.0,
                grade="F",
                strengths=[],
                gaps=["No measurements available"],
                recommendations=["Complete the exercise first"],
            )

        met = sum(1 for m in measurements if m.met_target)
        total = len(measurements)
        score = (met / total) * 100 if total else 0

        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        strengths = [f"{m.metric.value}: met target" for m in measurements if m.met_target]
        gaps = [
            f"{m.metric.value}: below target ({m.value:.1f} vs {m.target:.1f})"
            for m in measurements
            if not m.met_target
        ]
        recs = [f"Improve {m.metric.value}" for m in measurements if not m.met_target]

        category_scores = {
            m.metric.value: (min(m.value / m.target * 100, 100) if m.target > 0 else 0)
            for m in measurements
        }

        readiness = ReadinessScore(
            id=f"rs-{uuid4().hex[:12]}",
            overall_score=score,
            category_scores=category_scores,
            strengths=strengths,
            gaps=gaps,
            recommendations=recs,
            grade=grade,
        )

        logger.info(
            "simulator.readiness_scored",
            score=score,
            grade=grade,
        )

        return readiness
