"""Tests for hunt_hypothesis_generator."""

from __future__ import annotations

from shieldops.agents.hunt_hypothesis_generator.models import (
    GenerationStage,
    HuntHypothesisGeneratorState,
    HypothesisType,
    Priority,
)


class TestEnums:
    def test_generationstage(self) -> None:
        assert GenerationStage.ANALYZE_INTEL == "analyze_intel"
        assert len(GenerationStage) >= 3

    def test_hypothesistype(self) -> None:
        assert HypothesisType.BEHAVIORAL == "behavioral"
        assert len(HypothesisType) >= 3

    def test_priority(self) -> None:
        assert Priority.CRITICAL == "critical"
        assert len(Priority) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = HuntHypothesisGeneratorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = HuntHypothesisGeneratorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
