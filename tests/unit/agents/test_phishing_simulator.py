"""Tests for shieldops.agents.phishing_simulator."""

from __future__ import annotations

from shieldops.agents.phishing_simulator.models import (
    PhishingSimulatorState,
)


class TestModels:
    def test_state_defaults(self):
        s = PhishingSimulatorState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.phishing_simulator.graph import (
            create_phishing_simulator_graph,
        )

        sg = create_phishing_simulator_graph()
        assert sg.compile() is not None
