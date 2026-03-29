"""Tests for security_awareness_trainer."""

from __future__ import annotations

from shieldops.agents.security_awareness_trainer.models import (
    CompetencyLevel,
    SATStage,
    SecurityAwarenessTrainerState,
    TrainingTopic,
)


class TestEnums:
    def test_stage(self) -> None:
        assert SATStage.ASSESS_BASELINE == "assess_baseline"
        assert len(SATStage) >= 3

    def test_training_topic(self) -> None:
        assert TrainingTopic.PHISHING == "phishing"
        assert len(TrainingTopic) >= 3

    def test_competency_level(self) -> None:
        assert CompetencyLevel.EXPERT == "expert"
        assert len(CompetencyLevel) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SecurityAwarenessTrainerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SecurityAwarenessTrainerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
