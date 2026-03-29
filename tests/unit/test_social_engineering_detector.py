"""Tests for social_engineering_detector."""

from __future__ import annotations

from shieldops.agents.social_engineering_detector.models import (
    AttackTechnique,
    ConfidenceLevel,
    DetectionStage,
    SocialEngineeringDetectorState,
)


class TestEnums:
    def test_attacktechnique(self) -> None:
        assert AttackTechnique.PRETEXTING == "pretexting"
        assert len(AttackTechnique) >= 3

    def test_confidencelevel(self) -> None:
        assert ConfidenceLevel.HIGH == "high"
        assert len(ConfidenceLevel) >= 3

    def test_detectionstage(self) -> None:
        assert DetectionStage.COLLECT_SIGNALS == "collect_signals"
        assert len(DetectionStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SocialEngineeringDetectorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SocialEngineeringDetectorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
