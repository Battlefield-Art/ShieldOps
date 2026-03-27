"""Tests for shieldops.agents.sla_monitor."""

from __future__ import annotations

from shieldops.agents.sla_monitor.models import (
    SLAMonitorState,
)


class TestModels:
    def test_state_defaults(self):
        s = SLAMonitorState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.sla_monitor.graph import (
            create_sla_monitor_graph,
        )

        sg = create_sla_monitor_graph()
        assert sg.compile() is not None
