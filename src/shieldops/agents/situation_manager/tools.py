"""Tool functions for the Situation Manager Agent."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.situation_manager.models import (
    ActionRecommendation,
    AlertAggregate,
    OutcomeStatus,
    OutcomeTracking,
    PrioritizedSituation,
    SituationNarrative,
    SituationPriority,
)

logger = structlog.get_logger()


class SituationManagerToolkit:
    """Toolkit for situation management operations."""

    def __init__(
        self,
        alert_sources: Any | None = None,
        situation_store: Any | None = None,
        playbook_engine: Any | None = None,
        notification_service: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._alert_sources = alert_sources
        self._situation_store = situation_store
        self._playbook_engine = playbook_engine
        self._notification_service = notification_service
        self._policy_engine = policy_engine
        self._repository = repository

    async def aggregate_related_alerts(
        self,
        tenant_id: str,
        time_window_minutes: int = 60,
    ) -> list[AlertAggregate]:
        """Aggregate related alerts into groups."""
        logger.info(
            "situation_manager.aggregate",
            tenant_id=tenant_id,
            window=time_window_minutes,
        )
        if self._alert_sources is not None:
            try:
                return await self._alert_sources.aggregate(
                    tenant_id,
                    time_window_minutes,
                )
            except Exception:
                logger.warning("situation_manager.aggregate_fallback")
        return []

    async def compose_narrative(
        self,
        aggregates: list[AlertAggregate],
    ) -> list[SituationNarrative]:
        """Compose narratives for alert aggregates."""
        logger.info(
            "situation_manager.compose",
            count=len(aggregates),
        )
        narratives: list[SituationNarrative] = []
        for agg in aggregates:
            narratives.append(
                SituationNarrative(
                    id=f"narr-{uuid4().hex[:8]}",
                    aggregate_id=agg.id,
                    title=(
                        f"Situation: "
                        f"{agg.alert_count} alerts "
                        f"across "
                        f"{len(agg.source_vendors)} "
                        f"vendors"
                    ),
                    summary=(
                        f"Aggregated {agg.alert_count}"
                        f" alerts targeting "
                        f"{', '.join(agg.common_entities)}"
                    ),
                    affected_assets=(agg.common_entities),
                )
            )
        return narratives

    async def prioritize_situations(
        self,
        narratives: list[SituationNarrative],
        aggregates: list[AlertAggregate],
    ) -> list[PrioritizedSituation]:
        """Prioritize situations based on severity."""
        logger.info(
            "situation_manager.prioritize",
            count=len(narratives),
        )
        agg_map = {a.id: a for a in aggregates}
        situations: list[PrioritizedSituation] = []
        sev_priority = {
            "critical": (SituationPriority.P0_ACTIVE_ATTACK),
            "high": SituationPriority.P1_HIGH_RISK,
            "medium": (SituationPriority.P2_INVESTIGATION),
            "low": SituationPriority.P3_MONITORING,
            "info": (SituationPriority.P4_INFORMATIONAL),
        }
        for narr in narratives:
            agg = agg_map.get(narr.aggregate_id)
            sev = agg.severity if agg else "medium"
            priority = sev_priority.get(
                sev.lower(),
                SituationPriority.P3_MONITORING,
            )
            situations.append(
                PrioritizedSituation(
                    id=f"sit-{uuid4().hex[:8]}",
                    narrative_id=narr.id,
                    priority=priority,
                    title=narr.title,
                    severity=sev,
                    confidence=0.7,
                    vendor_count=(len(agg.source_vendors) if agg else 0),
                    alert_count=(agg.alert_count if agg else 0),
                )
            )
        return situations

    async def recommend_actions(
        self,
        situations: list[PrioritizedSituation],
    ) -> list[ActionRecommendation]:
        """Generate action recommendations."""
        logger.info(
            "situation_manager.recommend",
            count=len(situations),
        )
        recs: list[ActionRecommendation] = []
        for sit in situations:
            action_type = "investigate"
            urgency = "medium"
            if sit.priority in (
                SituationPriority.P0_ACTIVE_ATTACK,
                SituationPriority.P1_HIGH_RISK,
            ):
                action_type = "contain"
                urgency = "immediate"
            elif sit.priority == (SituationPriority.P2_INVESTIGATION):
                action_type = "investigate"
                urgency = "high"
            recs.append(
                ActionRecommendation(
                    id=f"rec-{uuid4().hex[:8]}",
                    situation_id=sit.id,
                    action_type=action_type,
                    description=(f"{action_type.title()} situation: {sit.title}"),
                    urgency=urgency,
                    automated=(sit.priority == SituationPriority.P4_INFORMATIONAL),
                    estimated_time_minutes=(15 if urgency == "immediate" else 30),
                )
            )
        return recs

    async def track_outcome(
        self,
        situations: list[PrioritizedSituation],
    ) -> list[OutcomeTracking]:
        """Initialize outcome tracking records."""
        logger.info(
            "situation_manager.track",
            count=len(situations),
        )
        outcomes: list[OutcomeTracking] = []
        for sit in situations:
            outcomes.append(
                OutcomeTracking(
                    id=f"out-{uuid4().hex[:8]}",
                    situation_id=sit.id,
                    status=OutcomeStatus.ONGOING,
                )
            )
        return outcomes
