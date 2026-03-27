"""Tests for shieldops.agents.situation_manager — situation aggregation and outcome tracking."""

from __future__ import annotations

import pytest

from shieldops.agents.situation_manager.models import (
    ActionRecommendation,
    AlertAggregate,
    OutcomeStatus,
    OutcomeTracking,
    PrioritizedSituation,
    ReasoningStep,
    SituationManagerState,
    SituationNarrative,
    SituationPriority,
    SituationStage,
)


def _state(**kw) -> SituationManagerState:
    return SituationManagerState(**kw)


class TestEnums:
    def test_situation_stage_values(self):
        assert SituationStage.AGGREGATE_ALERTS == "aggregate_alerts"
        assert SituationStage.COMPOSE_NARRATIVE == "compose_narrative"
        assert SituationStage.PRIORITIZE_SITUATIONS == "prioritize_situations"
        assert SituationStage.RECOMMEND_ACTIONS == "recommend_actions"
        assert SituationStage.TRACK_OUTCOMES == "track_outcomes"
        assert SituationStage.REPORT == "report"

    def test_situation_priority_values(self):
        assert SituationPriority.P0_ACTIVE_ATTACK == "p0_active_attack"
        assert SituationPriority.P1_HIGH_RISK == "p1_high_risk"
        assert SituationPriority.P2_INVESTIGATION == "p2_investigation"
        assert SituationPriority.P3_MONITORING == "p3_monitoring"
        assert SituationPriority.P4_INFORMATIONAL == "p4_informational"

    def test_outcome_status_values(self):
        assert OutcomeStatus.RESOLVED_AUTO == "resolved_auto"
        assert OutcomeStatus.RESOLVED_ANALYST == "resolved_analyst"
        assert OutcomeStatus.ESCALATED == "escalated"
        assert OutcomeStatus.FALSE_POSITIVE == "false_positive"
        assert OutcomeStatus.ONGOING == "ongoing"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.tenant_id == ""
        assert s.time_window_minutes == 60
        assert s.aggregates == []
        assert s.narratives == []
        assert s.situations == []
        assert s.recommendations == []
        assert s.outcomes == []
        assert s.total_alerts_processed == 0
        assert s.total_situations == 0
        assert s.auto_resolved_count == 0
        assert s.current_stage == SituationStage.AGGREGATE_ALERTS
        assert s.reasoning_chain == []
        assert s.error == ""
        assert s.session_duration_ms == 0

    def test_alert_aggregate_defaults(self):
        a = AlertAggregate()
        assert a.id == ""
        assert a.alert_ids == []
        assert a.source_vendors == []
        assert a.alert_count == 0
        assert a.time_span_seconds == 0.0
        assert a.raw_data == {}

    def test_situation_narrative_defaults(self):
        n = SituationNarrative()
        assert n.id == ""
        assert n.title == ""
        assert n.summary == ""
        assert n.attack_story == ""
        assert n.affected_assets == []
        assert n.timeline == []

    def test_prioritized_situation_defaults(self):
        p = PrioritizedSituation()
        assert p.id == ""
        assert p.priority == SituationPriority.P3_MONITORING
        assert p.confidence == 0.0
        assert p.auto_actionable is False

    def test_action_recommendation_defaults(self):
        a = ActionRecommendation()
        assert a.id == ""
        assert a.action_type == ""
        assert a.automated is False
        assert a.estimated_time_minutes == 0

    def test_outcome_tracking_defaults(self):
        o = OutcomeTracking()
        assert o.id == ""
        assert o.status == OutcomeStatus.ONGOING
        assert o.resolved_by == ""
        assert o.resolution_time_minutes == 0

    def test_reasoning_step_defaults(self):
        r = ReasoningStep()
        assert r.step_number == 0
        assert r.action == ""
        assert r.tool_used is None


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.situation_manager.tools import SituationManagerToolkit

        return SituationManagerToolkit()

    @pytest.mark.asyncio
    async def test_aggregate_related_alerts(self, toolkit):
        result = await toolkit.aggregate_related_alerts(tenant_id="t-01", time_window_minutes=30)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_compose_narrative(self, toolkit):
        aggregates = [AlertAggregate(id="agg-1", alert_count=3, severity="high")]
        result = await toolkit.compose_narrative(aggregates)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_prioritize_situations(self, toolkit):
        aggregates = [AlertAggregate(id="agg-1", alert_count=5, severity="critical")]
        narratives = [SituationNarrative(id="n-1", aggregate_id="agg-1", title="Test")]
        result = await toolkit.prioritize_situations(narratives, aggregates)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_recommend_actions(self, toolkit):
        situations = [PrioritizedSituation(id="sit-1", priority=SituationPriority.P1_HIGH_RISK)]
        result = await toolkit.recommend_actions(situations)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_track_outcome(self, toolkit):
        situations = [PrioritizedSituation(id="sit-1")]
        result = await toolkit.track_outcome(situations)
        assert isinstance(result, list)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.situation_manager.graph import create_situation_manager_graph

        sg = create_situation_manager_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.situation_manager.graph import create_situation_manager_graph

        sg = create_situation_manager_graph()
        compiled = sg.compile()
        assert compiled is not None
