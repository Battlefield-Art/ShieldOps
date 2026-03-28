"""Tool functions for the Security Awareness Agent."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_awareness.models import (
    DepartmentSummary,
    PhishingResult,
    RiskTier,
    SimulationType,
    TrainingRecord,
    UserRiskScore,
)

logger = structlog.get_logger()

# Sample simulation templates per type
SIMULATION_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "phishing_email": [
        {
            "subject": "Urgent: Password Reset Required",
            "difficulty": "easy",
            "expected_report_rate": 0.6,
        },
        {
            "subject": "Invoice #4821 Payment Overdue",
            "difficulty": "medium",
            "expected_report_rate": 0.4,
        },
        {
            "subject": "Shared Document: Q4 Strategy",
            "difficulty": "hard",
            "expected_report_rate": 0.2,
        },
    ],
    "smishing": [
        {
            "subject": "SMS: Verify your account",
            "difficulty": "medium",
            "expected_report_rate": 0.3,
        },
    ],
    "default": [
        {
            "subject": "Generic phishing attempt",
            "difficulty": "medium",
            "expected_report_rate": 0.4,
        },
    ],
}

SAMPLE_DEPARTMENTS = [
    "engineering",
    "finance",
    "marketing",
    "hr",
    "executive",
]


class SecurityAwarenessToolkit:
    """Toolkit for security awareness program management."""

    def __init__(
        self,
        awareness_db: Any | None = None,
    ) -> None:
        self._awareness_db = awareness_db

    async def assess_baseline(
        self,
        tenant_id: str,
    ) -> tuple[list[PhishingResult], list[TrainingRecord]]:
        """Assess current baseline from historical data."""
        now = time.time()
        phishing: list[PhishingResult] = []
        training: list[TrainingRecord] = []

        # Generate sample baseline data per department
        for dept in SAMPLE_DEPARTMENTS:
            for i in range(3):
                user_id = f"user-{dept[:3]}-{i}"
                email = f"{user_id}@example.com"
                clicked = i % 2 == 0
                reported = not clicked

                phishing.append(
                    PhishingResult(
                        id=f"ph-{uuid4().hex[:12]}",
                        user_id=user_id,
                        user_email=email,
                        department=dept,
                        simulation_type=SimulationType.PHISHING_EMAIL,
                        sent_at=now - 86400 * (30 - i),
                        opened=True,
                        clicked_link=clicked,
                        submitted_credentials=(clicked and dept == "executive"),
                        reported_phish=reported,
                        response_time_sec=120.0 + (i * 60),
                    )
                )

                passed = i != 2
                training.append(
                    TrainingRecord(
                        id=f"tr-{uuid4().hex[:12]}",
                        user_id=user_id,
                        user_email=email,
                        department=dept,
                        course_name="Security Fundamentals",
                        assigned_at=now - 86400 * 60,
                        completed_at=(now - 86400 * (30 - i) if passed else 0),
                        score_pct=85.0 if passed else 0.0,
                        passed=passed,
                        overdue=not passed,
                    )
                )

        logger.info(
            "awareness.baseline_assessed",
            tenant_id=tenant_id,
            phishing_count=len(phishing),
            training_count=len(training),
        )

        return phishing, training

    async def run_simulations(
        self,
        simulation_type: SimulationType,
        phishing_results: list[PhishingResult],
    ) -> list[PhishingResult]:
        """Run a new round of phishing simulations."""
        templates = SIMULATION_TEMPLATES.get(
            simulation_type.value,
            SIMULATION_TEMPLATES["default"],
        )
        now = time.time()
        new_results: list[PhishingResult] = []

        for dept in SAMPLE_DEPARTMENTS:
            for i, tmpl in enumerate(templates):
                user_id = f"user-{dept[:3]}-sim-{i}"
                email = f"{user_id}@example.com"
                # Simulate varying click rates by difficulty
                clicked = tmpl["difficulty"] == "hard" or (
                    tmpl["difficulty"] == "medium" and dept in ("finance", "hr")
                )
                reported = not clicked

                new_results.append(
                    PhishingResult(
                        id=f"ph-{uuid4().hex[:12]}",
                        user_id=user_id,
                        user_email=email,
                        department=dept,
                        simulation_type=simulation_type,
                        sent_at=now,
                        opened=True,
                        clicked_link=clicked,
                        submitted_credentials=False,
                        reported_phish=reported,
                        response_time_sec=90.0 + (i * 45),
                    )
                )

        logger.info(
            "awareness.simulations_run",
            simulation_type=simulation_type.value,
            count=len(new_results),
        )

        return [*phishing_results, *new_results]

    async def track_training(
        self,
        existing_records: list[TrainingRecord],
    ) -> list[TrainingRecord]:
        """Refresh training completion status."""
        now = time.time()
        updated: list[TrainingRecord] = []

        for rec in existing_records:
            overdue = (
                not rec.passed and rec.assigned_at > 0 and (now - rec.assigned_at) > 86400 * 30
            )
            updated.append(rec.model_copy(update={"overdue": overdue}))

        logger.info(
            "awareness.training_tracked",
            total=len(updated),
            overdue=sum(1 for r in updated if r.overdue),
        )

        return updated

    async def score_risk(
        self,
        phishing_results: list[PhishingResult],
        training_records: list[TrainingRecord],
    ) -> tuple[list[UserRiskScore], list[DepartmentSummary]]:
        """Calculate per-user and per-department risk scores."""
        # Group by user
        user_phish: dict[str, list[PhishingResult]] = {}
        for p in phishing_results:
            user_phish.setdefault(p.user_id, []).append(p)

        user_train: dict[str, list[TrainingRecord]] = {}
        for t in training_records:
            user_train.setdefault(t.user_id, []).append(t)

        all_users = set(user_phish) | set(user_train)
        scores: list[UserRiskScore] = []

        for uid in sorted(all_users):
            ph = user_phish.get(uid, [])
            tr = user_train.get(uid, [])

            fail_rate = sum(1 for p in ph if p.clicked_link) / len(ph) if ph else 0.0
            completion = sum(1 for t in tr if t.passed) / len(tr) if tr else 0.0
            avg_score = sum(t.score_pct for t in tr if t.passed) / max(
                sum(1 for t in tr if t.passed), 1
            )

            # Composite risk: higher = worse
            risk = fail_rate * 60 + (1 - completion) * 25 + (1 - avg_score / 100) * 15
            risk = min(max(risk, 0), 100)

            tier = self._classify_risk(risk)
            factors: list[str] = []
            if fail_rate > 0.5:
                factors.append("high_phishing_fail_rate")
            if completion < 0.8:
                factors.append("low_training_completion")
            if avg_score < 70:
                factors.append("low_training_scores")

            dept = ph[0].department if ph else (tr[0].department if tr else "unknown")

            scores.append(
                UserRiskScore(
                    id=f"rs-{uuid4().hex[:12]}",
                    user_id=uid,
                    user_email=f"{uid}@example.com",
                    department=dept,
                    phishing_fail_rate=round(
                        fail_rate * 100,
                        1,
                    ),
                    training_completion_pct=round(
                        completion * 100,
                        1,
                    ),
                    avg_training_score=round(avg_score, 1),
                    risk_score=round(risk, 1),
                    risk_tier=tier,
                    factors=factors,
                )
            )

        # Department summaries
        dept_users: dict[str, list[UserRiskScore]] = {}
        for s in scores:
            dept_users.setdefault(s.department, []).append(s)

        summaries: list[DepartmentSummary] = []
        for dept, users in sorted(dept_users.items()):
            avg_risk = sum(u.risk_score for u in users) / len(users)
            avg_fail = sum(u.phishing_fail_rate for u in users) / len(users)
            avg_completion = sum(u.training_completion_pct for u in users) / len(users)

            summaries.append(
                DepartmentSummary(
                    department=dept,
                    user_count=len(users),
                    avg_risk_score=round(avg_risk, 1),
                    risk_tier=self._classify_risk(avg_risk),
                    phishing_fail_rate=round(avg_fail, 1),
                    training_completion_pct=round(
                        avg_completion,
                        1,
                    ),
                )
            )

        logger.info(
            "awareness.risk_scored",
            users=len(scores),
            departments=len(summaries),
        )

        return scores, summaries

    async def generate_recommendations(
        self,
        risk_scores: list[UserRiskScore],
        department_summaries: list[DepartmentSummary],
    ) -> list[str]:
        """Generate improvement recommendations."""
        recs: list[str] = []

        high_risk = [s for s in risk_scores if s.risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH)]
        if high_risk:
            depts = {s.department for s in high_risk}
            recs.append(
                f"Enroll {len(high_risk)} high-risk users in "
                f"targeted phishing training "
                f"(departments: {', '.join(sorted(depts))})"
            )

        low_completion = [d for d in department_summaries if d.training_completion_pct < 80]
        if low_completion:
            for d in low_completion:
                recs.append(
                    f"Increase training enforcement for "
                    f"{d.department} "
                    f"(completion: {d.training_completion_pct}%)"
                )

        high_fail = [d for d in department_summaries if d.phishing_fail_rate > 40]
        if high_fail:
            for d in high_fail:
                recs.append(
                    f"Run additional phishing simulations for "
                    f"{d.department} "
                    f"(fail rate: {d.phishing_fail_rate}%)"
                )

        if not recs:
            recs.append("Maintain current awareness program cadence")

        logger.info(
            "awareness.recommendations_generated",
            count=len(recs),
        )

        return recs

    @staticmethod
    def _classify_risk(score: float) -> RiskTier:
        """Classify a risk score into a tier."""
        if score >= 80:
            return RiskTier.CRITICAL
        if score >= 60:
            return RiskTier.HIGH
        if score >= 40:
            return RiskTier.MEDIUM
        if score >= 20:
            return RiskTier.LOW
        return RiskTier.MINIMAL
