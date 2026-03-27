"""Tests for shieldops.agents.incident_commander."""

from __future__ import annotations

from shieldops.agents.incident_commander.models import (
    IncidentCommanderState,
)


class TestModels:
    def test_state_defaults(self):
        s = IncidentCommanderState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.incident_commander.graph import (
            create_incident_commander_graph,
        )

        sg = create_incident_commander_graph()
        assert sg.compile() is not None
