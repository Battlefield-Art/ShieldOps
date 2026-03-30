"""Security Awareness Engine Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from .models import (
    AwarenessBaseline,
    PhishingResult,
    RiskTier,
    TrainingCompletion,
    TrainingModule,
    TrainingPlan,
    UserRiskProfile,
)

logger = structlog.get_logger()

_DEPARTMENTS = [
    "Engineering",
    "Sales",
    "Marketing",
    "Finance",
    "HR",
    "Legal",
    "Support",
    "Executive",
]

_CAMPAIGNS = [
    ("C-001", "Fake Invoice", "Finance"),
    ("C-002", "Password Reset", "Engineering"),
    ("C-003", "CEO Gift Card", "Sales"),
    ("C-004", "IT Support Alert", "Support"),
    ("C-005", "Shared Document", "Marketing"),
    ("C-006", "Benefits Update", "HR"),
    ("C-007", "Board Meeting", "Executive"),
    ("C-008", "Compliance Notice", "Legal"),
]


def _generate_id(prefix: str, *parts: str) -> str:
    raw = f"{':'.join(parts)}:{datetime.now(UTC).isoformat()}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8].upper()
    return f"{prefix}-{h}"


class SecurityAwarenessEngineToolkit:
    """Tools for security awareness tracking and analysis."""

    def __init__(
        self,
        lms_client: Any | None = None,
        phishing_client: Any | None = None,
        hr_client: Any | None = None,
    ) -> None:
        self._lms = lms_client
        self._phishing = phishing_client
        self._hr = hr_client

    async def assess_baseline(
        self,
        tenant_id: str,
    ) -> list[AwarenessBaseline]:
        """Assess awareness baseline per department."""
        logger.info(
            "sae.assess_baseline",
            tenant_id=tenant_id,
        )

        if self._lms:
            try:
                return await self._lms.get_baselines(
                    tenant_id=tenant_id,
                )
            except Exception:
                logger.exception("sae.assess_baseline.error")

        rng = random.Random(42)  # noqa: S311
        now = datetime.now(UTC)
        baselines: list[AwarenessBaseline] = []

        for dept in _DEPARTMENTS:
            total = rng.randint(20, 200)  # noqa: S311
            trained = rng.randint(  # noqa: S311
                int(total * 0.4),
                total,
            )
            avg_score = round(  # noqa: S311
                rng.uniform(55.0, 95.0), 1
            )
            baselines.append(
                AwarenessBaseline(
                    department=dept,
                    total_users=total,
                    users_trained=trained,
                    avg_score=avg_score,
                    completion_rate=round(trained / total * 100, 1),
                    last_assessed=now
                    - timedelta(
                        days=rng.randint(1, 90)  # noqa: S311
                    ),
                )
            )

        return baselines

    async def get_phishing_results(
        self,
        tenant_id: str,
    ) -> list[PhishingResult]:
        """Retrieve phishing simulation campaign results."""
        logger.info(
            "sae.get_phishing_results",
            tenant_id=tenant_id,
        )

        if self._phishing:
            try:
                return await self._phishing.get_campaigns(
                    tenant_id=tenant_id,
                )
            except Exception:
                logger.exception("sae.phishing.error")

        rng = random.Random(43)  # noqa: S311
        now = datetime.now(UTC)
        results: list[PhishingResult] = []

        for cid, name, dept in _CAMPAIGNS:
            sent = rng.randint(50, 300)  # noqa: S311
            opened = rng.randint(  # noqa: S311
                int(sent * 0.3), int(sent * 0.9)
            )
            clicked = rng.randint(  # noqa: S311
                0, int(opened * 0.4)
            )
            creds = rng.randint(0, int(clicked * 0.3))  # noqa: S311
            reported = rng.randint(  # noqa: S311
                0, int(sent * 0.2)
            )

            results.append(
                PhishingResult(
                    campaign_id=cid,
                    campaign_name=name,
                    department=dept,
                    emails_sent=sent,
                    emails_opened=opened,
                    links_clicked=clicked,
                    credentials_submitted=creds,
                    reported_count=reported,
                    click_rate=round(clicked / sent * 100, 1) if sent else 0.0,
                    report_rate=round(reported / sent * 100, 1) if sent else 0.0,
                    run_date=now
                    - timedelta(
                        days=rng.randint(1, 60)  # noqa: S311
                    ),
                )
            )

        return results

    async def get_training_completions(
        self,
        tenant_id: str,
    ) -> list[TrainingCompletion]:
        """Retrieve training module completion records."""
        logger.info(
            "sae.get_training_completions",
            tenant_id=tenant_id,
        )

        if self._lms:
            try:
                return await self._lms.get_completions(
                    tenant_id=tenant_id,
                )
            except Exception:
                logger.exception("sae.training.error")

        rng = random.Random(44)  # noqa: S311
        now = datetime.now(UTC)
        completions: list[TrainingCompletion] = []

        for dept in _DEPARTMENTS:
            for i in range(rng.randint(5, 15)):  # noqa: S311
                module = rng.choice(  # noqa: S311
                    list(TrainingModule)
                )
                completed = rng.random() > 0.25  # noqa: S311
                score = (
                    round(  # noqa: S311
                        rng.uniform(50.0, 100.0), 1
                    )
                    if completed
                    else 0.0
                )

                completions.append(
                    TrainingCompletion(
                        user_id=f"user-{dept[:3].lower()}-{i:03d}",
                        department=dept,
                        module=module,
                        completed=completed,
                        score=score,
                        attempts=rng.randint(1, 3),  # noqa: S311
                        completed_at=now
                        - timedelta(
                            days=rng.randint(1, 120)  # noqa: S311
                        )
                        if completed
                        else None,
                        overdue=not completed and rng.random() > 0.5,  # noqa: S311
                    )
                )

        return completions

    async def build_risk_profiles(
        self,
        baselines: list[AwarenessBaseline],
        phishing_results: list[PhishingResult],
        completions: list[TrainingCompletion],
    ) -> list[UserRiskProfile]:
        """Build user risk profiles from awareness data."""
        logger.info("sae.build_risk_profiles")

        user_map: dict[str, UserRiskProfile] = {}

        for comp in completions:
            uid = comp.user_id
            if uid not in user_map:
                user_map[uid] = UserRiskProfile(
                    user_id=uid,
                    department=comp.department,
                )

            profile = user_map[uid]
            if comp.completed:
                profile.training_completion_pct = min(
                    profile.training_completion_pct + 16.7,
                    100.0,
                )
            if comp.overdue:
                profile.risk_factors.append(f"Overdue: {comp.module.value}")

        dept_click: dict[str, float] = {}
        for pr in phishing_results:
            dept_click[pr.department] = pr.click_rate

        for profile in user_map.values():
            click_rate = dept_click.get(profile.department, 0.0)
            profile.phishing_click_count = int(click_rate / 10)

            if click_rate > 25 or len(profile.risk_factors) > 2:
                profile.risk_tier = RiskTier.CRITICAL_RISK
                profile.recommended_modules = [
                    TrainingModule.PHISHING.value,
                    TrainingModule.SOCIAL_ENGINEERING.value,
                ]
            elif click_rate > 15 or len(profile.risk_factors) > 1:
                profile.risk_tier = RiskTier.HIGH_RISK
                profile.recommended_modules = [
                    TrainingModule.PHISHING.value,
                ]
            elif click_rate > 8:
                profile.risk_tier = RiskTier.MODERATE_RISK
            else:
                profile.risk_tier = RiskTier.LOW_RISK

        return list(user_map.values())

    async def generate_training_plans(
        self,
        risk_profiles: list[UserRiskProfile],
    ) -> list[TrainingPlan]:
        """Generate targeted training plans by risk tier."""
        logger.info("sae.generate_training_plans")

        tier_groups: dict[RiskTier, list[UserRiskProfile]] = {}
        for profile in risk_profiles:
            tier_groups.setdefault(profile.risk_tier, []).append(profile)

        plans: list[TrainingPlan] = []
        freq_map = {
            RiskTier.CRITICAL_RISK: "weekly",
            RiskTier.HIGH_RISK: "bi-weekly",
            RiskTier.MODERATE_RISK: "monthly",
            RiskTier.LOW_RISK: "quarterly",
            RiskTier.MINIMAL_RISK: "semi-annually",
        }

        for tier, profiles in tier_groups.items():
            depts = sorted({p.department for p in profiles})
            modules: set[str] = set()
            for p in profiles:
                modules.update(p.recommended_modules)

            if not modules:
                modules = {TrainingModule.PHISHING.value}

            plans.append(
                TrainingPlan(
                    plan_id=_generate_id("PLAN", tier.value),
                    target=", ".join(depts),
                    priority=tier,
                    modules=sorted(modules),
                    frequency=freq_map.get(tier, "quarterly"),
                    rationale=(
                        f"{len(profiles)} users at "
                        f"{tier.value} level across "
                        f"{len(depts)} departments"
                    ),
                    estimated_impact=(f"Reduce click rate by {min(len(profiles) * 2, 40)}%"),
                )
            )

        return plans
