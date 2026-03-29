"""Tests for kill_chain_analyzer."""

from __future__ import annotations

from shieldops.agents.kill_chain_analyzer.models import (
    AnalysisStage,
    CoverageLevel,
    KillChainAnalyzerState,
    KillChainPhase,
)


class TestEnums:
    def test_analysisstage(self) -> None:
        assert AnalysisStage.INGEST_ALERTS == "ingest_alerts"
        assert len(AnalysisStage) >= 3

    def test_coveragelevel(self) -> None:
        assert CoverageLevel.FULL == "full"
        assert len(CoverageLevel) >= 3

    def test_killchainphase(self) -> None:
        assert KillChainPhase.RECONNAISSANCE == "reconnaissance"
        assert len(KillChainPhase) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = KillChainAnalyzerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = KillChainAnalyzerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
