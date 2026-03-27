"""Tests for shieldops.agents.auto_learning."""

from __future__ import annotations

from shieldops.agents.auto_learning.models import (
    AutoLearningState,
    ExperimentOutcome,
    ExperimentType,
    LearningStage,
)


class TestEnums:
    def test_learningstage_assess(self):
        assert LearningStage.ASSESS == "assess"

    def test_learningstage_propose(self):
        assert LearningStage.PROPOSE == "propose"

    def test_learningstage_experiment(self):
        assert LearningStage.EXPERIMENT == "experiment"

    def test_learningstage_evaluate(self):
        assert LearningStage.EVALUATE == "evaluate"

    def test_experimenttype_threshold_tuning(self):
        assert ExperimentType.THRESHOLD_TUNING == "threshold_tuning"

    def test_experimenttype_alert_rule_update(self):
        assert ExperimentType.ALERT_RULE_UPDATE == "alert_rule_update"

    def test_experimenttype_runbook_refinement(self):
        assert ExperimentType.RUNBOOK_REFINEMENT == "runbook_refinement"

    def test_experimenttype_routing_optimization(self):
        assert ExperimentType.ROUTING_OPTIMIZATION == "routing_optimization"

    def test_experimentoutcome_accepted(self):
        assert ExperimentOutcome.ACCEPTED == "accepted"

    def test_experimentoutcome_rejected(self):
        assert ExperimentOutcome.REJECTED == "rejected"

    def test_experimentoutcome_inconclusive(self):
        assert ExperimentOutcome.INCONCLUSIVE == "inconclusive"

    def test_experimentoutcome_timed_out(self):
        assert ExperimentOutcome.TIMED_OUT == "timed_out"


class TestModels:
    def test_state_exists(self):
        assert AutoLearningState is not None


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.auto_learning.graph import build_graph
        from shieldops.agents.auto_learning.tools import AutoLearningToolkit

        sg = build_graph(AutoLearningToolkit())
        assert sg.compile() is not None
