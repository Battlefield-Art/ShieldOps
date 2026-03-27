"""Tests for shieldops.agents.soc_analyst."""

from __future__ import annotations

from shieldops.agents.soc_analyst.models import (
    SOCAnalystState,
)


class TestModels:
    def test_state_defaults(self):
        s = SOCAnalystState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.soc_analyst.graph import (
            create_soc_analyst_graph,
        )

        sg = create_soc_analyst_graph()
        assert sg.compile() is not None
