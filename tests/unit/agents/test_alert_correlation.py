"""Tests for shieldops.agents.alert_correlation."""

from __future__ import annotations

from shieldops.agents.alert_correlation.models import (
    AlertCorrelationState,
)


class TestModels:
    def test_state_defaults(self):
        s = AlertCorrelationState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.alert_correlation.graph import (
            create_alert_correlation_graph,
        )

        sg = create_alert_correlation_graph()
        assert sg.compile() is not None
