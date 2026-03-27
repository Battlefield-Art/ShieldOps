"""Tests for shieldops.agents.incident_response."""

from __future__ import annotations

from shieldops.agents.incident_response.models import (
    IncidentResponseState,
)


class TestModels:
    def test_state_defaults(self):
        s = IncidentResponseState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.incident_response.graph import (
            create_incident_response_graph,
        )

        sg = create_incident_response_graph()
        assert sg.compile() is not None
