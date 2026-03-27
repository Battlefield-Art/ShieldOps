"""Tests for shieldops.agents.cost_anomaly."""

from __future__ import annotations

from shieldops.agents.cost_anomaly.models import (
    CostAnomalyState,
)


class TestModels:
    def test_state_defaults(self):
        s = CostAnomalyState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.cost_anomaly.graph import (
            create_cost_anomaly_graph,
        )

        sg = create_cost_anomaly_graph()
        assert sg.compile() is not None
