"""Tests for playbook_optimizer."""

from __future__ import annotations

from shieldops.agents.playbook_optimizer.models import (
    BottleneckType,
    ImprovementStatus,
    OptimizationStage,
    PlaybookOptimizerState,
)


class TestEnums:
    def test_bottlenecktype(self) -> None:
        assert BottleneckType.SLOW_STEP == "slow_step"
        assert len(BottleneckType) >= 3

    def test_improvementstatus(self) -> None:
        assert ImprovementStatus.PROPOSED == "proposed"
        assert len(ImprovementStatus) >= 3

    def test_optimizationstage(self) -> None:
        assert OptimizationStage.ANALYZE_EXECUTIONS == "analyze_executions"
        assert len(OptimizationStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = PlaybookOptimizerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = PlaybookOptimizerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
