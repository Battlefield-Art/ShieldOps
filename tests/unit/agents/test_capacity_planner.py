"""Tests for shieldops.agents.capacity_planner."""

from __future__ import annotations

from shieldops.agents.capacity_planner.models import (
    CapacityPlannerState,
    CapacityRisk,
    CapacityStage,
    ResourceType,
)


class TestEnums:
    def test_capacitystage_collect_metrics(self):
        assert CapacityStage.COLLECT_METRICS == "collect_metrics"

    def test_capacitystage_forecast_demand(self):
        assert CapacityStage.FORECAST_DEMAND == "forecast_demand"

    def test_capacitystage_identify_bottlenecks(self):
        assert CapacityStage.IDENTIFY_BOTTLENECKS == "identify_bottlenecks"

    def test_capacitystage_plan_scaling(self):
        assert CapacityStage.PLAN_SCALING == "plan_scaling"

    def test_resourcetype_compute(self):
        assert ResourceType.COMPUTE == "compute"

    def test_resourcetype_memory(self):
        assert ResourceType.MEMORY == "memory"

    def test_resourcetype_storage(self):
        assert ResourceType.STORAGE == "storage"

    def test_resourcetype_network(self):
        assert ResourceType.NETWORK == "network"

    def test_capacityrisk_critical(self):
        assert CapacityRisk.CRITICAL == "critical"

    def test_capacityrisk_high(self):
        assert CapacityRisk.HIGH == "high"

    def test_capacityrisk_medium(self):
        assert CapacityRisk.MEDIUM == "medium"

    def test_capacityrisk_low(self):
        assert CapacityRisk.LOW == "low"


class TestModels:
    def test_state_defaults(self):
        s = CapacityPlannerState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.capacity_planner.graph import (
            create_capacity_planner_graph,
        )

        sg = create_capacity_planner_graph()
        assert sg.compile() is not None
