"""Tests for cloud_cost_optimizer."""

from __future__ import annotations

from shieldops.agents.cloud_cost_optimizer.models import (
    CCOStage,
    CloudCostOptimizerState,
    CostCategory,
    SavingsPotential,
)


class TestEnums:
    def test_stage(self) -> None:
        assert CCOStage.COLLECT_BILLING == "collect_billing"
        assert len(CCOStage) >= 3

    def test_cost_category(self) -> None:
        assert CostCategory.COMPUTE == "compute"
        assert len(CostCategory) >= 3

    def test_savings_potential(self) -> None:
        assert SavingsPotential.HIGH == "high"
        assert len(SavingsPotential) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = CloudCostOptimizerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = CloudCostOptimizerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
