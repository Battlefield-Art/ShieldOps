"""Tests for shieldops.agents.incident_triage."""

from __future__ import annotations

from shieldops.agents.incident_triage.models import (
    IncidentTriageState,
)


class TestModels:
    def test_state_defaults(self):
        s = IncidentTriageState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.incident_triage.graph import (
            create_incident_triage_graph,
        )

        sg = create_incident_triage_graph()
        assert sg.compile() is not None
