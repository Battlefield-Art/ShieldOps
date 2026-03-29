"""Tests for inference_attack_detector."""

from __future__ import annotations

from shieldops.agents.inference_attack_detector.models import (
    AttackStage,
    AttackType,
    InferenceAttackDetectorState,
)


class TestEnums:
    def test_attackstage(self) -> None:
        assert AttackStage.COLLECT_QUERIES == "collect_queries"
        assert len(AttackStage) >= 3

    def test_attacktype(self) -> None:
        assert AttackType.MODEL_INVERSION == "model_inversion"
        assert len(AttackType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = InferenceAttackDetectorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = InferenceAttackDetectorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
