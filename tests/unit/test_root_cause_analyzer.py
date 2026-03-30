"""Tests for root_cause_analyzer."""

from __future__ import annotations

from shieldops.agents.root_cause_analyzer.models import (
    CausalityConfidence,
    RCAStage,
    RootCauseAnalyzerState,
    SignalSource,
)


class TestEnums:
    def test_stage(self) -> None:
        assert RCAStage.COLLECT_SIGNALS == "collect_signals"
        assert len(RCAStage) >= 3

    def test_signal_source(self) -> None:
        assert SignalSource.METRICS == "metrics"
        assert len(SignalSource) >= 3

    def test_causality_confidence(self) -> None:
        assert CausalityConfidence.DEFINITIVE == "definitive"
        assert len(CausalityConfidence) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = RootCauseAnalyzerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = RootCauseAnalyzerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
