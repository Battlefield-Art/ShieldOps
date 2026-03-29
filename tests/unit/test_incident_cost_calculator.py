"""Tests for incident_cost_calculator."""

from __future__ import annotations

from shieldops.agents.incident_cost_calculator.models import (
    CalculationStage,
    CostCategory,
    CostConfidence,
    IncidentCostCalculatorState,
)


class TestEnums:
    def test_calculationstage(self) -> None:
        assert CalculationStage.GATHER_METRICS == "gather_metrics"
        assert len(CalculationStage) >= 3

    def test_costcategory(self) -> None:
        assert CostCategory.RESPONSE == "response"
        assert len(CostCategory) >= 3

    def test_costconfidence(self) -> None:
        assert CostConfidence.ACTUAL == "actual"
        assert len(CostConfidence) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = IncidentCostCalculatorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = IncidentCostCalculatorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
