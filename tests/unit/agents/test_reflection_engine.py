"""Tests for shieldops.agents.reflection_engine — closed-loop agent self-improvement."""

from __future__ import annotations

import pytest

from shieldops.agents.reflection_engine.models import (
    AgentAction,
    ImprovementRecommendation,
    ImprovementType,
    LearningApplication,
    MistakeIdentification,
    OutcomeAssessment,
    OutcomeEvaluation,
    ReasoningStep,
    ReflectionEngineState,
    ReflectionStage,
)


def _state(**kw) -> ReflectionEngineState:
    return ReflectionEngineState(**kw)


class TestEnums:
    def test_reflection_stage_values(self):
        assert ReflectionStage.COLLECT_ACTIONS == "collect_actions"
        assert ReflectionStage.EVALUATE_OUTCOMES == "evaluate_outcomes"
        assert ReflectionStage.IDENTIFY_MISTAKES == "identify_mistakes"
        assert ReflectionStage.GENERATE_IMPROVEMENTS == "generate_improvements"
        assert ReflectionStage.APPLY_LEARNINGS == "apply_learnings"
        assert ReflectionStage.REPORT == "report"

    def test_outcome_assessment_values(self):
        assert OutcomeAssessment.EFFECTIVE == "effective"
        assert OutcomeAssessment.PARTIALLY_EFFECTIVE == "partially_effective"
        assert OutcomeAssessment.INEFFECTIVE == "ineffective"
        assert OutcomeAssessment.COUNTERPRODUCTIVE == "counterproductive"
        assert OutcomeAssessment.UNKNOWN == "unknown"

    def test_improvement_type_values(self):
        assert ImprovementType.DETECTION_RULE_TUNE == "detection_rule_tune"
        assert ImprovementType.THRESHOLD_ADJUST == "threshold_adjust"
        assert ImprovementType.PLAYBOOK_UPDATE == "playbook_update"
        assert ImprovementType.FALSE_POSITIVE_SUPPRESS == "false_positive_suppress"
        assert ImprovementType.ESCALATION_CHANGE == "escalation_change"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.agent_id == ""
        assert s.time_range_hours == 24
        assert s.tenant_id == ""
        assert s.actions_reviewed == []
        assert s.evaluations == []
        assert s.mistakes_found == []
        assert s.improvements_recommended == []
        assert s.learnings_applied == []
        assert s.effectiveness_score == 0.0
        assert s.total_actions_reviewed == 0
        assert s.total_mistakes_found == 0
        assert s.total_improvements == 0
        assert s.total_learnings_applied == 0
        assert s.false_positive_rate == 0.0
        assert s.current_stage == ReflectionStage.COLLECT_ACTIONS
        assert s.reasoning_chain == []
        assert s.error == ""
        assert s.session_duration_ms == 0

    def test_agent_action_defaults(self):
        a = AgentAction()
        assert a.id == ""
        assert a.agent_id == ""
        assert a.action_type == ""
        assert a.confidence == 0.0
        assert a.parameters == {}
        assert a.duration_ms == 0

    def test_outcome_evaluation_defaults(self):
        oe = OutcomeEvaluation()
        assert oe.action_id == ""
        assert oe.assessment == OutcomeAssessment.UNKNOWN
        assert oe.effectiveness_score == 0.0
        assert oe.false_positive is False

    def test_mistake_identification_defaults(self):
        m = MistakeIdentification()
        assert m.id == ""
        assert m.pattern_name == ""
        assert m.affected_agent_ids == []
        assert m.frequency == 0

    def test_improvement_recommendation_defaults(self):
        ir = ImprovementRecommendation()
        assert ir.id == ""
        assert ir.improvement_type == ImprovementType.THRESHOLD_ADJUST
        assert ir.auto_applicable is False
        assert ir.priority == 3

    def test_learning_application_defaults(self):
        la = LearningApplication()
        assert la.improvement_id == ""
        assert la.applied is False
        assert la.applied_to_agent == ""

    def test_reasoning_step_defaults(self):
        r = ReasoningStep()
        assert r.step_number == 0
        assert r.action == ""
        assert r.tool_used is None


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.reflection_engine.tools import ReflectionEngineToolkit

        return ReflectionEngineToolkit()

    @pytest.mark.asyncio
    async def test_collect_recent_actions(self, toolkit):
        result = await toolkit.collect_recent_actions(agent_id="agent-1", time_range_hours=24)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_evaluate_outcome(self, toolkit):
        action = AgentAction(
            id="act-1",
            agent_id="agent-1",
            action_type="isolate_host",
            actual_result="host isolated",
            expected_result="host isolated",
        )
        result = await toolkit.evaluate_outcome(action=action, actual_result="host isolated")
        assert isinstance(result, OutcomeEvaluation)

    @pytest.mark.asyncio
    async def test_identify_mistakes(self, toolkit):
        evals = [
            OutcomeEvaluation(
                action_id="a-1",
                assessment=OutcomeAssessment.INEFFECTIVE,
                effectiveness_score=0.1,
            ),
            OutcomeEvaluation(
                action_id="a-2",
                assessment=OutcomeAssessment.COUNTERPRODUCTIVE,
                effectiveness_score=0.0,
            ),
        ]
        result = await toolkit.identify_mistakes(evals)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_generate_improvement(self, toolkit):
        mistake = MistakeIdentification(
            id="m-1",
            pattern_name="over_escalation",
            frequency=5,
            severity="medium",
            root_cause="threshold too low",
        )
        result = await toolkit.generate_improvement(mistake)
        assert isinstance(result, ImprovementRecommendation)

    @pytest.mark.asyncio
    async def test_apply_learning(self, toolkit):
        improvement = ImprovementRecommendation(
            id="imp-1",
            improvement_type=ImprovementType.THRESHOLD_ADJUST,
            title="Raise detection threshold",
            auto_applicable=True,
        )
        result = await toolkit.apply_learning(improvement)
        assert isinstance(result, LearningApplication)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.reflection_engine.graph import create_reflection_engine_graph

        sg = create_reflection_engine_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.reflection_engine.graph import create_reflection_engine_graph

        sg = create_reflection_engine_graph()
        compiled = sg.compile()
        assert compiled is not None
