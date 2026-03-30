"""Tool functions for the Security Training Platform Agent."""

from __future__ import annotations

import random  # noqa: S311
from typing import Any
from uuid import uuid4

import structlog

logger = structlog.get_logger()


class SecurityTrainingPlatformToolkit:
    """Toolkit for security training operations."""

    def __init__(
        self,
        user_directory: Any | None = None,
        email_sender: Any | None = None,
        lms_client: Any | None = None,
        risk_engine: Any | None = None,
        analytics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._user_directory = user_directory
        self._email_sender = email_sender
        self._lms_client = lms_client
        self._risk_engine = risk_engine
        self._analytics_store = analytics_store
        self._repository = repository

    async def assess_baseline(
        self,
        training_config: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Assess baseline security awareness per team."""
        teams = training_config.get("teams", [])
        logger.info(
            "stp.assess_baseline",
            team_count=len(teams),
        )
        assessments: list[dict[str, Any]] = []
        for team in teams:
            name = team if isinstance(team, str) else team.get("name", "unknown")
            assessments.append(
                {
                    "team_id": f"tm-{uuid4().hex[:8]}",
                    "team_name": name,
                    "user_count": random.randint(5, 50),  # noqa: S311
                    "avg_awareness_score": round(
                        random.uniform(30, 85),  # noqa: S311
                        1,
                    ),
                    "phishing_click_rate": round(
                        random.uniform(0.05, 0.45),  # noqa: S311
                        2,
                    ),
                    "compliance_completion": round(
                        random.uniform(0.4, 1.0),  # noqa: S311
                        2,
                    ),
                    "last_training": None,
                    "weaknesses": [],
                }
            )
        return assessments

    async def create_campaign(
        self,
        assessments: list[dict[str, Any]],
        training_config: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Create training campaigns based on assessments."""
        logger.info(
            "stp.create_campaign",
            assessment_count=len(assessments),
        )
        campaigns: list[dict[str, Any]] = []
        for assessment in assessments:
            click_rate = assessment.get("phishing_click_rate", 0.2)
            ctype = "phishing" if click_rate > 0.3 else "compliance"
            campaigns.append(
                {
                    "campaign_id": f"cp-{uuid4().hex[:8]}",
                    "campaign_type": ctype,
                    "target_teams": [assessment.get("team_id", "")],
                    "target_user_count": assessment.get("user_count", 0),
                    "difficulty": ("hard" if click_rate > 0.3 else "medium"),
                    "duration_days": 7,
                    "description": (f"{ctype} campaign for {assessment.get('team_name', '')}"),
                    "metadata": {},
                }
            )
        return campaigns

    async def deploy_simulation(
        self,
        campaigns: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Deploy training simulations for campaigns."""
        logger.info(
            "stp.deploy_simulation",
            campaign_count=len(campaigns),
        )
        results: list[dict[str, Any]] = []
        for campaign in campaigns:
            user_count = campaign.get("target_user_count", 10)
            for _i in range(min(user_count, 5)):
                clicked = random.random() < 0.25  # noqa: S311
                results.append(
                    {
                        "simulation_id": (f"sim-{uuid4().hex[:8]}"),
                        "campaign_id": campaign.get("campaign_id", ""),
                        "user_id": f"u-{uuid4().hex[:8]}",
                        "team_id": (campaign.get("target_teams", [""])[0]),
                        "action_taken": ("clicked" if clicked else "ignored"),
                        "time_to_action_ms": (
                            random.randint(  # noqa: S311
                                1000, 60000
                            )
                        ),
                        "reported_suspicious": (
                            random.random() > 0.7  # noqa: S311
                        ),
                        "clicked_link": clicked,
                        "entered_credentials": (
                            clicked and random.random() < 0.3  # noqa: S311
                        ),
                        "score": round(
                            random.uniform(  # noqa: S311
                                20, 100
                            ),
                            1,
                        ),
                    }
                )
        return results

    async def track_results(
        self,
        simulation_results: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Track and aggregate simulation results."""
        logger.info(
            "stp.track_results",
            result_count=len(simulation_results),
        )
        return simulation_results

    async def score_risk(
        self,
        tracked_results: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Score risk for users and teams."""
        logger.info(
            "stp.score_risk",
            result_count=len(tracked_results),
        )
        # Aggregate by team
        team_data: dict[str, list[dict[str, Any]]] = {}
        for r in tracked_results:
            tid = r.get("team_id", "unknown")
            team_data.setdefault(tid, []).append(r)

        scores: list[dict[str, Any]] = []
        for tid, results in team_data.items():
            click_rate = sum(1 for r in results if r.get("clicked_link")) / max(len(results), 1)
            avg_score = sum(r.get("score", 0) for r in results) / max(len(results), 1)
            risk = round(100 - avg_score + (click_rate * 30), 1)
            tier = (
                "critical"
                if risk > 70
                else "high"
                if risk > 50
                else "medium"
                if risk > 30
                else "low"
            )
            scores.append(
                {
                    "entity_id": tid,
                    "entity_type": "team",
                    "risk_tier": tier,
                    "risk_score": min(risk, 100),
                    "click_rate": round(click_rate, 2),
                    "training_completion": round(
                        random.uniform(0.5, 1.0),  # noqa: S311
                        2,
                    ),
                    "improvement_trend": round(
                        random.uniform(-5, 15),  # noqa: S311
                        1,
                    ),
                    "recommended_training": [],
                }
            )
        return scores

    async def record_metric(
        self,
        metric_type: str,
        value: float,
    ) -> None:
        """Record a security training metric."""
        logger.info(
            "stp.record_metric",
            metric_type=metric_type,
            value=value,
        )
