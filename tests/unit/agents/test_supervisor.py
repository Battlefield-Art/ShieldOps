"""Tests for shieldops.agents.supervisor."""

from __future__ import annotations

from shieldops.agents.supervisor.models import (
    SupervisorState,
)


class TestModels:
    def test_state_defaults(self):
        s = SupervisorState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.supervisor.graph import (
            create_supervisor_graph,
        )

        sg = create_supervisor_graph()
        assert sg.compile() is not None
