"""Tests for shieldops.agents.telemetry_optimizer."""

from __future__ import annotations

from shieldops.agents.telemetry_optimizer.models import (
    TelemetryOptimizerState,
)


class TestModels:
    def test_state_defaults(self):
        s = TelemetryOptimizerState(request_id="r-01", tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.telemetry_optimizer.graph import (
            create_telemetry_optimizer_graph,
        )

        sg = create_telemetry_optimizer_graph()
        assert sg.compile() is not None
